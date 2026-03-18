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
) where

import Cardano.Api qualified as C
import Control.Monad (unless, void)
import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Trans (lift)
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (getUtxo)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.DatumBloat (datumByteBloatAttackWith)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
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

import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, assertFailure, testCase)
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
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the TipJar V2 contract
data TipJarV2Model = TipJarV2Model
  { tmOwner :: PlutusTx.BuiltinByteString
  -- ^ Owner's pubkey hash
  , tmMessages :: [PlutusTx.BuiltinByteString]
  -- ^ Accumulated messages
  , tmValue :: C.Lovelace
  -- ^ Value locked in the tipjar
  , tmTxIn :: C.TxIn
  -- ^ Number of tips added (used to prevent wallet fund exhaustion)
  , tmHasBeenClaimed :: Bool
  -- ^ Once claimed, sequence is done
  }
  deriving stock (Show, Eq)

instance TestingInterface TipJarV2Model where
  -- Actions for TipJar V2: initialize, add tips, and owner claims
  data Action TipJarV2Model
    = TipV2 PlutusTx.BuiltinByteString
    | -- \^ Add a tip with a message
      OwnerClaimV2
    -- \^ Owner claims all funds and closes the tipjar
    deriving stock (Show, Eq)

  initialize = do
    let txBody = execBuildTx $ initTipJarV2 @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
    void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    let ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
     in pure $
          TipJarV2Model
            { tmOwner = ownerBytes
            , tmMessages = []
            , tmValue = 10_000_000
            , tmTxIn = C.TxIn dummyTxId (C.TxIx 0)
            , tmHasBeenClaimed = False
            }

  -- Generate actions: init-type actions TIGHT, spending actions BROAD.
  -- Init creates fresh UTxO (always succeeds on Cardano) - only when not initialized.
  -- Spending actions can fail on-chain - generate even when invalid for negative testing.
  arbitraryAction _model =
    QC.frequency
      [ (17, TipV2 <$> genMessage)
      , (3, pure OwnerClaimV2)
      ]
   where
    genMessage = do
      len <- QC.choose (1, 50)
      bytes <- BS.pack <$> QC.vectorOf len (QC.choose (0x20, 0x7E)) -- printable ASCII
      pure $ PlutusTx.toBuiltin bytes

  precondition model _ = not (tmHasBeenClaimed model)

  nextState model action = case action of
    TipV2 msg ->
      -- Messages are prepended (Aiken list.push adds to head)
      model
        { tmMessages = msg : tmMessages model
        , tmValue = tmValue model + 5_000_000
        }
    OwnerClaimV2 ->
      -- Claiming resets the model and marks as claimed (sequence ends)
      model
        { tmMessages = []
        , tmValue = 0
        , tmHasBeenClaimed = True -- Mark as claimed
        }

  perform _model action = case action of
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
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
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
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

  validate model = do
    -- Query the actual state from the blockchain
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos = utxoSet
        scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarV2Address) utxos
    case Map.toList scriptUtxos of
      [] ->
        -- No UTxO found - tipjar must have been claimed
        pure (tmHasBeenClaimed model)
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
              tjOwner actualDatum == tmOwner model
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

  monitoring _state _action prop = prop

  -- Threat models to test vulnerability detection.
  -- Note: We intentionally exclude datumByteBloatAttackWith and largeValueAttackWith here
  -- because they WOULD find vulnerabilities (which is expected for this contract).
  -- Including unprotectedScriptOutput and largeDataAttackWith for basic coverage.
  threatModels = [unprotectedScriptOutput]

  -- Expected vulnerabilities: threat models that SHOULD find vulnerabilities.
  -- V2 is STILL vulnerable to datum bloat (no message size limit) and large value
  -- attacks (value_preserved only prevents REMOVAL, not ADDITION of tokens).
  expectedVulnerabilities = [datumByteBloatAttackWith 1000, largeValueAttackWith 10, largeDataAttackWith 10]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All Aiken TipJar V2 tests grouped together
aikenTipJarV2Tests :: RunOptions -> TestTree
aikenTipJarV2Tests runOpts =
  testGroup
    "aiken tip-jar-v2 (partial patch)"
    [ aikenTipJarV2UnitTests
    , propRunActionsWithOptions @TipJarV2Model
        "property-based testing"
        runOpts
    ]
