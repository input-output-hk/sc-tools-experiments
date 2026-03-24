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

{- | Tests for the Aiken-compiled TipJar validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable Aiken contract.
The TipJar validator allows anyone to add tips with messages, and the owner can
claim the accumulated funds. However, it has vulnerabilities:

1. No limit on message size (Large Data Attack)
2. No validation of output value structure (Large Value Attack)

The Aiken types encode as:
- @Datum { owner: VerificationKeyHash, messages: List<ByteArray> }@ = @Constr 0 [owner_bytes, list_of_bytestrings]@
- @Redeemer: Claim | AddTip@ = @Constr 0 [] | Constr 1 []@
-}
module AikenTipJarSpec (
  -- * TestingInterface model
  TipJarModel (..),

  -- * Test tree
  aikenTipJarTests,
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
-- ----------------------------------------------------------------------------

-- | Load the Aiken "tipjar" validator from the embedded blueprint
loadTipJarScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadTipJarScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_tipjar.ctf_tipjar.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_tipjar.ctf_tipjar.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken TipJar script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE aikenTipJarScript #-}
aikenTipJarScript :: C.PlutusScript C.PlutusScriptV3
aikenTipJarScript = unsafePerformIO loadTipJarScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the tipjar script
tipJarScriptHash :: C.ScriptHash
tipJarScriptHash = C.hashScript (plutusScript aikenTipJarScript)

-- | Address of the tipjar script on the default network
tipJarAddress :: C.AddressInEra C.ConwayEra
tipJarAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript tipJarScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Initialize the tipjar by paying to the script with an initial datum.

The owner is derived from the given wallet's pubkey hash.
-}
initTipJar
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -> C.Lovelace
  -> m ()
initTipJar networkId wallet initialValue = do
  let ownerPkh = verificationKeyHash wallet
      -- Convert to BuiltinByteString
      ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes ownerPkh
      datum = TipJarDatum{tjOwner = ownerBytes, tjMessages = []}
  BuildTx.payToScriptInlineDatum
    networkId
    tipJarScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Add a tip to the tipjar: spend the current UTxO, add a message, increase value.

This uses the AddTip redeemer and creates a new UTxO with:
- Same owner
- Message appended to the messages list
- Value increased by tipAmount
-}
addTip
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
addTip networkId txIn oldDatum currentValue tipAmount message = do
  -- NOTE: Aiken's list.push adds to the HEAD, so we prepend the message
  let newDatum =
        oldDatum
          { tjMessages = message : tjMessages oldDatum
          }
      newValue = C.lovelaceToValue (currentValue + tipAmount)
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            aikenTipJarScript
            (C.ScriptDatumForTxIn Nothing)
            AddTip
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.payToScriptInlineDatum
    networkId
    tipJarScriptHash
    newDatum
    C.NoStakeAddress
    newValue

{- | Owner claims the tipjar: spend the UTxO and send funds to the owner.

Uses the Claim redeemer. The owner's signature is required (handled by balancing).
-}
claimJar
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
claimJar networkId txIn value ownerWallet = do
  let ownerAddr = addressInEra networkId ownerWallet
      ownerPkh = verificationKeyHash ownerWallet
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            aikenTipJarScript
            (C.ScriptDatumForTxIn Nothing)
            Claim
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature ownerPkh
  BuildTx.payToAddress ownerAddr value

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenTipJarUnitTests :: TestTree
aikenTipJarUnitTests =
  testGroup
    "aiken tipjar unit tests"
    [ testCase "initialize tipjar" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initTipJar Defaults.networkId Wallet.w1 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    , testCase "add a tip" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initTipJar Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                message = PlutusTx.toBuiltin ("Hello" :: BS.ByteString)
            -- Add tip
            let tipTxBody = execBuildTx $ addTip Defaults.networkId txIn initialDatum 10_000_000 5_000_000 message
            void $ tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []
    , testCase "owner claims tipjar" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with wallet 1 as owner
            let initTxBody = execBuildTx $ initTipJar Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                message = PlutusTx.toBuiltin ("Hello" :: BS.ByteString)

            -- Add a tip from wallet 2
            let tipTxBody = execBuildTx $ addTip Defaults.networkId txIn initialDatum 10_000_000 5_000_000 message
            _ <- tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []

            -- Find the updated tipjar UTxO
            utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
            let C.UTxO utxos = utxoSet
                scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos
            (tipJarTxIn, tipJarValue) <- case Map.toList scriptUtxos of
              [(ti, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _)] ->
                pure (ti, C.fromMaryValue val)
              _ -> fail "Expected exactly one tipjar UTxO after tip"

            -- Owner (wallet 1) claims all funds
            let claimTxBody = execBuildTx $ claimJar Defaults.networkId tipJarTxIn tipJarValue Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 claimTxBody TrailingChange []
    , testCase "add tip with huge message (vulnerability!)" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initTipJar Defaults.networkId Wallet.w1 10_000_000
            initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
            let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
                initialDatum = TipJarDatum{tjOwner = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1), tjMessages = []}
                -- Create a massive 1000-byte message - this SHOULD succeed since the contract is vulnerable!
                hugeMessage = PlutusTx.toBuiltin (BS.replicate 1000 0x41) -- 1000 'A's
                -- Add tip with huge message
            let tipTxBody = execBuildTx $ addTip Defaults.networkId txIn initialDatum 10_000_000 5_000_000 hugeMessage
            void $ tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []
    , testCase "huge message permanently locks tipjar" hugeMessagePermanentlyLocksTipjar
    ]

{- | Test that demonstrates a huge message can make the tipjar unusable for new tips.

This test proves the vulnerability by:
1. Initializing a tipjar
2. Adding a tip with a huge message (~14KB) - this succeeds
3. Attempting to add another tiny tip - this FAILS (script execution or tx size error)
4. Verifying that the owner can still CLAIM (funds are not locked)

The key insight: With inline datums, the datum is stored in the UTxO output, NOT in the
transaction witness set. This means:
- TIP transactions: include the full datum in the OUTPUT → counts toward tx size limit
- CLAIM transactions: reference the input UTxO's inline datum → NO datum in tx body

A TIP tx near the limit (~15KB datum) can succeed, but any subsequent tip FAILS. The
failure may occur due to:
- Transaction size exceeding the 16KB limit (MaxTxSizeUTxO)
- Script execution errors during balancing (e.g., datum comparison issues with large data)
- Other resource limits (memory, CPU)

This is a attack: the funds can still be claimed by the owner, but the
tipjar becomes permanently unusable for accepting new tips.
-}
hugeMessagePermanentlyLocksTipjar :: Assertion
hugeMessagePermanentlyLocksTipjar = do
  -- Use a message size that:
  -- 1. Fits in the TIP transaction (datum in output, ~15KB total tx)
  -- 2. Prevents any future tips (output datum would exceed 16KB limit)
  --
  -- The max tx size is 16384 bytes.
  -- Testing showed: 14500 bytes → tip tx = 16489 bytes (too large)
  --                 14000 bytes → tip tx ≈ 15989 bytes (fits, leaves ~400 bytes)
  --
  -- Any subsequent tip would add to the datum, exceeding the limit.
  let hugeMessageSize = 14_000

  -- Run the test directly in MockchainIO
  _ <- runMockchain0IOWith Wallet.initialUTxOs Defaults.nodeParams $ failOnError $ do
    -- Step 1: Initialize tipjar with w1 as owner
    let initTxBody = execBuildTx $ initTipJar @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
    initTx <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []
    let txIn = C.TxIn (C.getTxId (C.getTxBody initTx)) (C.TxIx 0)
        ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
        initialDatum = TipJarDatum{tjOwner = ownerBytes, tjMessages = []}

    -- Step 2: Add a tip with a HUGE message - this is the attack!
    -- A 14KB datum requires ~60 ADA of min-UTxO
    let hugeMsg = PlutusTx.toBuiltin (BS.replicate hugeMessageSize 0x41) -- 14000 'A's
    -- Provide 60 ADA as tip (current value 10 + tip 60 = 70 ADA, exceeds min-UTxO)
        tipTxBody = execBuildTx $ addTip @C.ConwayEra Defaults.networkId txIn initialDatum 10_000_000 60_000_000 hugeMsg

    -- The tip transaction should succeed (datum in output, tx is ~16KB)
    _ <- tryBalanceAndSubmit mempty Wallet.w2 tipTxBody TrailingChange []

    -- Step 3: Find the bloated tipjar UTxO
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos = utxoSet
        scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos
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
    -- The new output datum would be: existing 14KB + 2 bytes = exceeds tx size limit
    let tinyMsg = PlutusTx.toBuiltin ("hi" :: BS.ByteString)
        newTipTxBody = execBuildTx $ addTip @C.ConwayEra Defaults.networkId txIn2 bloatedDatum (C.selectLovelace tipJarValue) 1_000_000 tinyMsg
    -- Use runExceptT to catch balancing errors (like MaxTxSizeUTxO or script execution errors)
    newTipResult <- lift $ runExceptT $ balanceAndSubmit mempty Wallet.w3 newTipTxBody TrailingChange []
    case newTipResult of
      Left _err -> pure () -- Expected: balancing fails (datum too large for new tx)
      Right (Left _err) -> pure () -- Expected: validation fails
      Right (Right _) -> liftIO $ assertFailure "ERROR: New tip should have failed! The tipjar should be unusable."

    -- Step 5: Verify owner can still CLAIM - funds are NOT locked
    -- Re-fetch the UTxO (it wasn't spent by the failed tip)
    utxoSet2 <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos2 = utxoSet2
        scriptUtxos2 = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos2
    (txIn3, tipJarValue2) <- case Map.toList scriptUtxos2 of
      [(ti, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _)] ->
        pure (ti, C.fromMaryValue val)
      _ -> fail "Expected exactly one tipjar UTxO"

    let claimTxBody = execBuildTx $ claimJar @C.ConwayEra Defaults.networkId txIn3 tipJarValue2 Wallet.w1
    claimResult <- balanceAndSubmit mempty Wallet.w1 claimTxBody TrailingChange []
    case claimResult of
      Left err -> liftIO $ assertFailure $ "ERROR: Claim should have succeeded! Error: " ++ show err
      Right _ -> pure ()

    pure ()

  -- The test passes if we got here - the assertions inside verified:
  -- 1. Huge tip succeeded
  -- 2. New tip failed (during balancing - script execution error or tx size)
  -- 3. Claim succeeded (owner can still recover funds)
  pure ()

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the TipJar contract
data TipJarModel = TipJarModel
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

instance TestingInterface TipJarModel where
  -- Actions for TipJar: initialize, add tips, and owner claims
  data Action TipJarModel
    = Tip PlutusTx.BuiltinByteString
    | -- \^ Add a tip with a message
      OwnerClaim
    -- \^ Owner claims all funds and closes the tipjar
    deriving stock (Show, Eq)

  initialize = do
    let txBody = execBuildTx $ initTipJar @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
    void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    let ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
    pure $
      TipJarModel
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
      [ (17, Tip <$> genMessage)
      , (3, pure OwnerClaim)
      ]
   where
    genMessage = do
      len <- QC.choose (1, 50)
      bytes <- BS.pack <$> QC.vectorOf len (QC.choose (0x20, 0x7E)) -- printable ASCII
      pure $ PlutusTx.toBuiltin bytes

  precondition model _ = not (tmHasBeenClaimed model)

  nextState model action = case action of
    Tip msg ->
      -- Messages are prepended (Aiken list.push adds to head)
      model
        { tmMessages = msg : tmMessages model
        , tmValue = tmValue model + 5_000_000
        }
    OwnerClaim ->
      -- Claiming resets the model and marks as claimed (sequence ends)
      model
        { tmMessages = []
        , tmValue = 0
        , tmHasBeenClaimed = True
        }

  perform _model action = case action of
    Tip msg -> do
      -- liftIO $ putStrLn $ "[TipJar] Adding tip with message length: " ++ show (PlutusTx.lengthOfByteString msg)
      -- Find the UTxO at the script address
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos
      case Map.toList scriptUtxos of
        [] -> fail "No UTxO found at tipjar script address"
        ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) datum _) : _) -> do
          let lovelace = C.selectLovelace (C.fromMaryValue val)
          -- Extract datum
          currentDatum <- case datum of
            C.TxOutDatumInline _ scriptData ->
              pure $
                unsafeFromBuiltinData @TipJarDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
            _ -> fail "Expected inline datum"
          let txBody = execBuildTx $ addTip @C.ConwayEra Defaults.networkId txIn currentDatum lovelace 5_000_000 msg
          -- NOTE: Using w1 for tips because the threat model re-balancer uses w1 for re-signing.
          -- The threat model's rebalanceAndSignTx looks for a change output to the wallet address.
          -- If we used w2 here, the threat model would fail with "No change output found".
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    OwnerClaim -> do
      -- liftIO $ putStrLn "[TipJar] Owner claiming tipjar"
      -- Find the UTxO at the script address
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos
      case Map.toList scriptUtxos of
        [] -> fail "No UTxO found at tipjar script address for claim"
        ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) : _) -> do
          let tipJarValue = C.fromMaryValue val
              txBody = execBuildTx $ claimJar @C.ConwayEra Defaults.networkId txIn tipJarValue Wallet.w1
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

  validate model = do
    -- Query the actual state from the blockchain
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos = utxoSet
        scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == tipJarAddress) utxos
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
  -- Note: largeDataAttackWith, largeValueAttackWith, and datumByteBloatAttackWith
  -- all FAIL (detecting vulnerabilities), so only unprotectedScriptOutput is included.
  threatModels = [unprotectedScriptOutput, largeDataAttackWith 10]

  -- Expected vulnerabilities: threat models that SHOULD find vulnerabilities.
  -- These are run with inverted pass/fail semantics.
  expectedVulnerabilities = [datumByteBloatAttackWith 1000, largeValueAttackWith 10]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All Aiken TipJar tests grouped together
aikenTipJarTests :: RunOptions -> TestTree
aikenTipJarTests runOpts =
  testGroup
    "aiken tip-jar"
    [ aikenTipJarUnitTests
    , propRunActionsWithOptions @TipJarModel
        "property-based testing"
        runOpts
    ]
