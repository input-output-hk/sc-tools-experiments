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

{- | Tests for the Aiken-compiled TipJar V2 validator using TestingInterface.

This module demonstrates property-based testing of a PARTIALLY PATCHED Aiken contract.
The TipJar V2 validator is similar to V1 but adds a value-preservation check.

WHAT V2 PATCHES:
- Token theft: value_preserved check ensures output >= input for all assets
  This prevents attackers from STEALING existing tokens

WHAT V2 DOES NOT PATCH:
1. Datum Bloat Attack - message sizes are still unbounded
2. Large Value Attack - the check only prevents REMOVAL, not ADDITION of tokens
   The threat model ADDS new junk tokens, which passes value_preserved!

This makes V2 an educational example of an incomplete fix - it addresses one
attack vector (theft) but leaves others (bloat attacks) wide open.

The Aiken types encode as:
- @Datum { owner: VerificationKeyHash, messages: List<ByteArray> }@ = @Constr 0 [owner_bytes, list_of_bytestrings]@
- @Redeemer: Claim | AddTip@ = @Constr 0 [] | Constr 1 []@
-}
module AikenTipJarV2Spec (
  -- * TestingInterface model
  TipJarV2Model (..),

  -- * Test tree
  aikenTipJarV2Tests,

  -- * Standalone threat model tests
  propTipJarV2StillVulnerableToByteBloat,
  propTipJarV2StillVulnerableToLargeValue,
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
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (ThreatModelEnv (..), runThreatModelM)
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.DatumBloat (datumByteBloatAttackWith)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.ByteString qualified as BS
import Data.Map qualified as Map

import Paths_convex_testing_interface qualified as Pkg
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))

import Convex.ThreatModel.LargeData (largeDataAttackWith)
import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertFailure, testCase)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
  testProperty,
 )
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- TipJar Datum and Redeemer types (wire-compatible with Aiken)
-- Same as V1 - the datum/redeemer types are identical
-- ----------------------------------------------------------------------------

{- | The datum stored at the tipjar script address.

Aiken encodes this as: @Constr 0 [owner_bytes, list_of_bytestrings]@
-}
data TipJarDatum = TipJarDatum
  { tjOwner :: PlutusTx.BuiltinByteString
  -- ^ The pubkey hash of the owner who can claim
  , tjMessages :: [PlutusTx.BuiltinByteString]
  -- ^ List of messages from tippers
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the tipjar.

Aiken encodes as: @Claim = Constr 0 []@, @AddTip = Constr 1 []@
-}
data TipJarRedeemer = Claim | AddTip
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''TipJarDatum
PlutusTx.unstableMakeIsData ''TipJarRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- Changed: key is "ctf_tipjar_v2.ctf_tipjar_v2.spend" instead of "tipjar.tipjar.spend"
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_tipjar_v2" validator from the embedded blueprint
loadTipJarV2Script :: IO (C.PlutusScript C.PlutusScriptV3)
loadTipJarV2Script = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_tipjar_v2.ctf_tipjar_v2.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_tipjar_v2.ctf_tipjar_v2.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken TipJar V2 script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE aikenTipJarV2Script #-}
aikenTipJarV2Script :: C.PlutusScript C.PlutusScriptV3
aikenTipJarV2Script = unsafePerformIO loadTipJarV2Script

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the tipjar v2 script
tipJarV2ScriptHash :: C.ScriptHash
tipJarV2ScriptHash = C.hashScript (plutusScript aikenTipJarV2Script)

-- | Address of the tipjar v2 script on the default network
tipJarV2Address :: C.AddressInEra C.ConwayEra
tipJarV2Address =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript tipJarV2ScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Transaction builders
-- Same structure as V1, but uses the V2 script
-- ----------------------------------------------------------------------------

{- | Initialize the tipjar v2 by paying to the script with an initial datum.

The owner is derived from the given wallet's pubkey hash.
-}
initTipJarV2
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -> C.Lovelace
  -> m ()
initTipJarV2 networkId wallet initialValue = do
  let ownerPkh = verificationKeyHash wallet
      -- Convert to BuiltinByteString
      ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes ownerPkh
      datum = TipJarDatum{tjOwner = ownerBytes, tjMessages = []}
  BuildTx.payToScriptInlineDatum
    networkId
    tipJarV2ScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Add a tip to the tipjar v2: spend the current UTxO, add a message, increase value.

This uses the AddTip redeemer and creates a new UTxO with:
- Same owner
- Message appended to the messages list
- Value increased by tipAmount
-}
addTipV2
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -> TipJarDatum
  -> C.Lovelace
  -> C.Lovelace
  -> PlutusTx.BuiltinByteString
  -> m ()
addTipV2 networkId txIn oldDatum currentValue tipAmount message = do
  -- NOTE: Aiken's list.push adds to the HEAD, so we prepend the message
  let newDatum =
        oldDatum
          { tjMessages = message : tjMessages oldDatum
          }
      newValue = C.lovelaceToValue (currentValue + tipAmount)
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            aikenTipJarV2Script
            (C.ScriptDatumForTxIn Nothing)
            AddTip
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.payToScriptInlineDatum
    networkId
    tipJarV2ScriptHash
    newDatum
    C.NoStakeAddress
    newValue

{- | Owner claims the tipjar v2: spend the UTxO and send funds to the owner.

Uses the Claim redeemer. The owner's signature is required (handled by balancing).
-}
claimJarV2
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -> C.Value
  -> Wallet
  -> m ()
claimJarV2 networkId txIn value ownerWallet = do
  let ownerAddr = addressInEra networkId ownerWallet
      ownerPkh = verificationKeyHash ownerWallet
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            aikenTipJarV2Script
            (C.ScriptDatumForTxIn Nothing)
            Claim
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature ownerPkh
  BuildTx.payToAddress ownerAddr value

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenTipJarV2UnitTests :: TestTree
aikenTipJarV2UnitTests =
  testGroup
    "aiken tipjar v2 unit tests"
    [ testCase "initialize tipjar v2" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initTipJarV2 Defaults.networkId Wallet.w1 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    , testCase "add a tip" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initTipJarV2 Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                message = PlutusTx.toBuiltin ("Hello" :: BS.ByteString)
            -- Add tip
            let tipTxBody = execBuildTx $ addTipV2 Defaults.networkId txIn initialDatum 10_000_000 5_000_000 message
            void $ tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []
    , testCase "owner claims tipjar v2" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with wallet 1 as owner
            let initTxBody = execBuildTx $ initTipJarV2 Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                message = PlutusTx.toBuiltin ("Hello" :: BS.ByteString)

            -- Add a tip from wallet 2
            let tipTxBody = execBuildTx $ addTipV2 Defaults.networkId txIn initialDatum 10_000_000 5_000_000 message
            _ <- tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []

            -- Find the updated tipjar UTxO
            utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
            let C.UTxO utxos = utxoSet
                scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
            (tipJarTxIn, tipJarValue) <- case Map.toList scriptUtxos of
              [(ti, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _)] ->
                pure (ti, C.fromMaryValue val)
              _ -> fail "Expected exactly one tipjar UTxO after tip"

            -- Owner (wallet 1) claims all funds
            let claimTxBody = execBuildTx $ claimJarV2 Defaults.networkId tipJarTxIn tipJarValue Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 claimTxBody TrailingChange []
    , testCase "add tip with huge message (datum bloat still works!)" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initTipJarV2 Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                -- Create a massive 1000-byte message - this SHOULD succeed since datum bloat is NOT patched!
                hugeMessage = PlutusTx.toBuiltin (BS.replicate 1000 0x41) -- 1000 'A's
                -- Add tip with huge message
            let tipTxBody = execBuildTx $ addTipV2 Defaults.networkId txIn initialDatum 10_000_000 5_000_000 hugeMessage
            void $ tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []
    , testCase "huge message permanently locks tipjar v2 (datum bloat DoS)" hugeMessagePermanentlyLocksTipjarV2
    ]

{- | Test that demonstrates a huge message can make the tipjar v2 unusable for new tips.

This is the SAME vulnerability as V1 - the value preservation check does NOT help here.
The datum bloat attack still works because message sizes are unbounded.

This test proves the remaining vulnerability by:
1. Initializing a tipjar v2
2. Adding a tip with a huge message (~13.5KB) - this succeeds
3. Attempting to add another tiny tip - this FAILS (script execution or tx size error)
4. Verifying that the owner can still CLAIM (funds are not locked)

NOTE: V2 script is slightly larger than V1, so we use 13500 bytes instead of 14000.
-}
hugeMessagePermanentlyLocksTipjarV2 :: Assertion
hugeMessagePermanentlyLocksTipjarV2 = do
  -- V2 script is larger than V1, so we need slightly smaller message
  let hugeMessageSize = 13_500

  -- Run the test directly in MockchainIO
  _ <- runMockchain0IOWith Wallet.initialUTxOs Defaults.nodeParams $ failOnError $ do
    -- Step 1: Initialize tipjar v2 with w1 as owner
    let initTxBody = execBuildTx $ initTipJarV2 @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
    initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
    let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
        ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
        initialDatum = TipJarDatum{tjOwner = ownerBytes, tjMessages = []}

    -- Step 2: Add a tip with a HUGE message - this is the attack!
    let hugeMsg = PlutusTx.toBuiltin (BS.replicate hugeMessageSize 0x41) -- 14000 'A's
        tipTxBody = execBuildTx $ addTipV2 @C.ConwayEra Defaults.networkId txIn initialDatum 10_000_000 60_000_000 hugeMsg

    -- The tip transaction should succeed (datum in output, tx is ~16KB)
    _ <- tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []

    -- Step 3: Find the bloated tipjar UTxO
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos = utxoSet
        scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
    (txIn2, tipJarValue, bloatedDatum) <- case Map.toList scriptUtxos of
      [(ti, C.TxOut _ (C.TxOutValueShelleyBased _ val) datum _)] -> do
        currentDatum <- case datum of
          C.TxOutDatumInline _ scriptData ->
            pure $
              unsafeFromBuiltinData @TipJarDatum
                (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
          _ -> fail "Expected inline datum"
        pure (ti, C.fromMaryValue val, currentDatum)
      _ -> fail "Expected exactly one tipjar UTxO after huge tip"

    -- Step 4: Try to add another tiny tip - this should FAIL!
    let tinyMsg = PlutusTx.toBuiltin ("hi" :: BS.ByteString)
        newTipTxBody = execBuildTx $ addTipV2 @C.ConwayEra Defaults.networkId txIn2 bloatedDatum (C.selectLovelace tipJarValue) 1_000_000 tinyMsg
    newTipResult <- lift $ runExceptT $ balanceAndSubmit mempty Wallet.w3 newTipTxBody TrailingChange []
    case newTipResult of
      Left _err -> pure () -- Expected: balancing fails (datum too large for new tx)
      Right (Left _err) -> pure () -- Expected: validation fails
      Right (Right _) -> liftIO $ assertFailure "ERROR: New tip should have failed! The tipjar v2 should be unusable due to datum bloat."

    -- Step 5: Verify owner can still CLAIM - funds are NOT locked
    utxoSet2 <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos2 = utxoSet2
        scriptUtxos2 = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos2
    (txIn3, tipJarValue2) <- case Map.toList scriptUtxos2 of
      [(ti, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _)] ->
        pure (ti, C.fromMaryValue val)
      _ -> fail "Expected exactly one tipjar UTxO"

    let claimTxBody = execBuildTx $ claimJarV2 @C.ConwayEra Defaults.networkId txIn3 tipJarValue2 Wallet.w1
    claimResult <- balanceAndSubmit mempty Wallet.w1 claimTxBody TrailingChange []
    case claimResult of
      Left err -> liftIO $ assertFailure $ "ERROR: Claim should have succeeded! Error: " ++ show err
      Right _ -> pure ()

    pure ()

  pure ()

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Run a tipjar v2 scenario: initialize + add one tip.

Returns the last transaction (the tip transaction) and the UTxO state
captured BEFORE that transaction executed, for threat model testing.
-}
tipJarV2Scenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
tipJarV2Scenario = do
  -- Initialize the tipjar v2 with wallet 1 as owner
  let initTxBody = execBuildTx $ initTipJarV2 Defaults.networkId Wallet.w1 10_000_000
  initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

  -- Find the tipjar UTxO
  let initTxIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
      initialDatum =
        TipJarDatum
          { tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
          , tjMessages = []
          }
      message = PlutusTx.toBuiltin ("Hello" :: BS.ByteString)

  -- Capture UTxO BEFORE adding the tip (for threat model)
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- Add a tip - using w1 because threat model re-balancer uses w1 for re-signing
  let tipTxBody = execBuildTx $ addTipV2 Defaults.networkId initTxIn initialDatum 10_000_000 5_000_000 message
  tipTx <- tryBalanceAndSubmit mempty Wallet.w1 tipTxBody TrailingChange []

  pure (tipTx, utxoBefore)

{- | Test that the tipjar v2 is STILL vulnerable to datum byte bloat attack.

This test runs the datumByteBloatAttackWith threat model against a tipjar v2
transaction. The threat model attempts to inflate ByteString fields in the
datum (like the message) to detect if the validator limits field sizes.

Since the tipjar v2 validator STILL does NOT limit message sizes (only adds
value preservation), this test will FAIL - proving the vulnerability REMAINS.

Use QC.expectFailure to mark this as expected behavior.
-}
propTipJarV2StillVulnerableToByteBloat :: RunOptions -> Property
propTipJarV2StillVulnerableToByteBloat opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- tipJarV2Scenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    lift $ runThreatModelM Wallet.w1 (datumByteBloatAttackWith 1000) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing tipjar v2 for datum byte bloat vulnerability (STILL VULNERABLE)")
      pure prop

{- | Test that the tipjar v2 is STILL vulnerable to large value attack.

IMPORTANT: The V2 validator's value_preserved check only ensures no tokens can be
REMOVED from the script (all value differences must be >= 0). However, the
largeValueAttack ADDS new junk tokens to the output - it doesn't try to remove
existing tokens. Since value_preserved allows additions (output >= input), this
attack still works!

The value preservation check prevents:
- Stealing existing tokens (output value < input value for some asset)

But it does NOT prevent:
- Adding new junk tokens (output has more assets than input)
- Datum bloat attacks

So V2 is still vulnerable to large value attacks because the threat model
mints and adds new tokens rather than trying to steal existing ones.

Use QC.expectFailure because the threat model WILL detect the vulnerability.
-}
propTipJarV2StillVulnerableToLargeValue :: RunOptions -> Property
propTipJarV2StillVulnerableToLargeValue opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- tipJarV2Scenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    lift $ runThreatModelM Wallet.w1 (largeValueAttackWith 10) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing tipjar v2 for large value attack (STILL VULNERABLE - adds tokens, doesn't remove)")
      pure prop

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the TipJar V2 contract
data TipJarV2Model = TipJarV2Model
  { tmInitialized :: Bool
  -- ^ Whether the tipjar has been created
  , tmOwner :: Maybe PlutusTx.BuiltinByteString
  -- ^ Owner's pubkey hash
  , tmMessages :: [PlutusTx.BuiltinByteString]
  -- ^ Accumulated messages
  , tmValue :: C.Lovelace
  -- ^ Value locked in the tipjar
  , tmTxIn :: Maybe C.TxIn
  -- ^ Number of tips added (used to prevent wallet fund exhaustion)
  , tmHasBeenClaimed :: Bool
  -- ^ Once claimed, sequence is done - no re-initialization allowed
  }
  deriving stock (Show, Eq)

instance TestingInterface TipJarV2Model where
  -- Actions for TipJar V2: initialize, add tips, and owner claims
  data Action TipJarV2Model
    = InitTipJarV2
    | -- \^ Initialize the tipjar v2 (w1 as owner)
      TipV2 PlutusTx.BuiltinByteString
    | -- \^ Add a tip with a message
      OwnerClaimV2
    -- \^ Owner claims all funds and closes the tipjar
    deriving stock (Show, Eq)

  initialState =
    TipJarV2Model
      { tmInitialized = False
      , tmOwner = Nothing
      , tmMessages = []
      , tmValue = 0
      , tmTxIn = Nothing
      , tmHasBeenClaimed = False
      }

  -- Generate actions: init-type actions TIGHT, spending actions BROAD.
  -- Init creates fresh UTxO (always succeeds on Cardano) - only when not initialized.
  -- Spending actions can fail on-chain - generate even when invalid for negative testing.
  arbitraryAction model
    | not (tmInitialized model) && not (tmHasBeenClaimed model) = pure InitTipJarV2
    | otherwise =
        QC.frequency
          [ (17, TipV2 <$> genMessage)
          , (3, pure OwnerClaimV2)
          ]
   where
    genMessage = do
      len <- QC.choose (1, 50)
      bytes <- BS.pack <$> QC.vectorOf len (QC.choose (0x20, 0x7E)) -- printable ASCII
      pure $ PlutusTx.toBuiltin bytes

  precondition model InitTipJarV2 = not (tmInitialized model) && not (tmHasBeenClaimed model)
  precondition model (TipV2 _) = tmInitialized model
  precondition model OwnerClaimV2 = tmInitialized model

  nextState model action = case action of
    InitTipJarV2 ->
      let ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
       in model
            { tmInitialized = True
            , tmOwner = Just ownerBytes
            , tmMessages = []
            , tmValue = 10_000_000
            , tmTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
            , tmHasBeenClaimed = False
            }
    TipV2 msg ->
      -- Messages are prepended (Aiken list.push adds to head)
      model
        { tmMessages = msg : tmMessages model
        , tmValue = tmValue model + 5_000_000
        }
    OwnerClaimV2 ->
      -- Claiming resets the model and marks as claimed (sequence ends)
      TipJarV2Model
        { tmInitialized = False
        , tmOwner = Nothing
        , tmMessages = []
        , tmValue = 0
        , tmTxIn = Nothing
        , tmHasBeenClaimed = True -- Mark as claimed - no re-init allowed
        }

  perform _model action = case action of
    InitTipJarV2 -> do
      let txBody = execBuildTx $ initTipJarV2 @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to initialize tipjar v2: " ++ show err
        Right _ -> pure ()
    TipV2 msg -> do
      -- Find the UTxO at the script address
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
      case Map.toList scriptUtxos of
        [] -> fail "No UTxO found at tipjar v2 script address"
        ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) datum _) : _) -> do
          let lovelace = C.selectLovelace (C.fromMaryValue val)
          -- Extract datum
          currentDatum <- case datum of
            C.TxOutDatumInline _ scriptData ->
              pure $
                unsafeFromBuiltinData @TipJarDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
            _ -> fail "Expected inline datum"
          let txBody = execBuildTx $ addTipV2 @C.ConwayEra Defaults.networkId txIn currentDatum lovelace 5_000_000 msg
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to add tip: " ++ show err
            Right _ -> pure ()
    OwnerClaimV2 -> do
      -- Find the UTxO at the script address
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
      case Map.toList scriptUtxos of
        [] -> fail "No UTxO found at tipjar v2 script address for claim"
        ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) : _) -> do
          let tipJarValue = C.fromMaryValue val
              txBody = execBuildTx $ claimJarV2 @C.ConwayEra Defaults.networkId txIn tipJarValue Wallet.w1
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to claim tipjar v2: " ++ show err
            Right _ -> pure ()

  validate model = case tmTxIn model of
    Nothing -> pure True -- No tipjar deployed
    Just _ -> do
      -- Query the actual state from the blockchain
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
      case Map.toList scriptUtxos of
        [] ->
          -- No UTxO found - tipjar must have been claimed
          pure (not $ tmInitialized model)
        ((_, C.TxOut _ (C.TxOutValueShelleyBased _ val) datum _) : _) -> do
          -- Check value matches model
          let actualLovelace = C.selectLovelace (C.fromMaryValue val)
              valueMatches = actualLovelace == tmValue model
          -- Check datum matches model
          datumMatches <- case datum of
            C.TxOutDatumInline _ scriptData -> do
              let actualDatum =
                    unsafeFromBuiltinData @TipJarDatum
                      (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              pure $
                tjOwner actualDatum == maybe "" id (tmOwner model)
                  && tjMessages actualDatum == tmMessages model
            _ -> pure False
          unless (valueMatches && datumMatches) $
            liftIO $
              putStrLn $
                "STATE MISMATCH! Model value: "
                  ++ show (tmValue model)
                  ++ ", Blockchain: "
                  ++ show actualLovelace
          pure (valueMatches && datumMatches)
   where
    unless True _ = pure ()
    unless False m = m

  monitoring _state _action prop = prop

  -- Threat models to test vulnerability detection.
  -- Note: We intentionally exclude datumByteBloatAttackWith and largeValueAttackWith here
  -- because they WOULD find vulnerabilities (which is expected for this contract).
  -- Those vulnerability tests are run separately with expectFailure in the standalone tests.
  -- Including unprotectedScriptOutput and largeDataAttackWith for basic coverage.
  threatModels = [unprotectedScriptOutput, largeDataAttackWith 10]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All Aiken TipJar V2 tests grouped together
aikenTipJarV2Tests :: RunOptions -> TestTree
aikenTipJarV2Tests runOpts =
  testGroup
    "aiken tip-jar-v2 (partial patch)"
    [ aikenTipJarV2UnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @TipJarV2Model
            "property-based testing"
            runOpts
        , testProperty
            "STILL vulnerable to datum byte bloat (expectFailure)"
            -- The tipjar v2 IS STILL vulnerable to datum bloat (doesn't limit message sizes)
            -- We use expectFailure because the threat model WILL detect the vulnerability
            (QC.expectFailure $ propTipJarV2StillVulnerableToByteBloat runOpts)
        , testProperty
            "STILL vulnerable to large value attack (v2 only prevents removal, not addition)"
            -- The tipjar v2 value_preserved check only prevents token REMOVAL
            -- The large value attack ADDS new tokens, so it still works!
            (QC.expectFailure $ propTipJarV2StillVulnerableToLargeValue runOpts)
        ]
    ]
