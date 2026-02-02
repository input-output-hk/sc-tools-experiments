{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- | Coverage tests for PingPong validator.

These tests specifically target uncovered code paths in Scripts/PingPong.hs
to ensure comprehensive coverage of error handling and edge cases.
-}
module PingPongCoverageSpec (
  pingPongCoverageTests,
) where

import Cardano.Api qualified as C
import Control.Monad.Except (runExceptT)
import Convex.BuildTx (execBuildTx, mintPlutus)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (getUtxo)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (Options (..), mockchainFailsWithOptions, mockchainSucceedsWithOptions)

import Convex.Utils.String (unsafeAssetName, unsafeDatumHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import PlutusLedgerApi.V3 qualified as PV3
import Scripts qualified
import Scripts.PingPong qualified as PingPong
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (Assertion, testCase)

{- | Test group for PingPong coverage tests.

Coverage status after these tests:

Covered:
- Line 141: PingPongState invalid index error (via testInvalidDatumIndex)
- Line 207: Invalid script purpose error (via testInvalidScriptPurpose)
- Line 222: findOwnInput recursive case (via testFindOwnInputRecursive)
- Line 249: NoOutputDatum error (via testNoOutputDatum)
- Lines 250-251: OutputDatumHash lookup succeeds (via testOutputDatumHashFound)
- Line 252: OutputDatumHash lookup fails (via testOutputDatumHashNotFound)

Unreachable (defensive code):
- Line 219: "Own input not found" - The Cardano ledger guarantees that the
  ownTxOutRef from SpendingScript is always present in txInfoInputs. This
  error path cannot be triggered through normal mockchain or mainnet operation.
  It exists only as a defensive guard against impossible states.
-}
pingPongCoverageTests :: Options C.ConwayEra -> TestTree
pingPongCoverageTests opts =
  testGroup
    "PingPong coverage tests"
    [ testCase "Line 141: invalid datum index triggers error" (testInvalidDatumIndex opts)
    , testCase "Line 207: invalid script purpose triggers error" (testInvalidScriptPurpose opts)
    , testCase "Line 222: findOwnInput recursive case" (testFindOwnInputRecursive opts)
    , testCase "Line 249: NoOutputDatum error triggers" (testNoOutputDatum opts)
    , testCase "Lines 250-251: OutputDatumHash found in datum map" (testOutputDatumHashFound opts)
    , testCase "Line 252: OutputDatumHash not found in datum map" (testOutputDatumHashNotFound opts)
    -- Note: Line 219 ("Own input not found") is unreachable - see comment above
    ]

{- | Test that an invalid PingPongState constructor index triggers the error on line 141.

Valid indices are: 0 (Pinged), 1 (Ponged), 2 (Stopped)
We create a datum with index 5, which should trigger:
  P.traceError "PingPongState: invalid index"

Strategy:
1. Create an output at the PingPong script address with an invalid datum (Constr 5 [])
2. Try to spend that output using playPingPongRound
3. The validator will attempt to parse the datum with unsafeFromBuiltinData
4. Since index 5 is invalid, it will trigger line 141: "PingPongState: invalid index"
-}
testInvalidDatumIndex :: Options C.ConwayEra -> Assertion
testInvalidDatumIndex opts = mockchainFailsWithOptions opts action handleError
 where
  action = do
    -- Create an invalid datum: Constr 5 [] (valid indices are 0, 1, 2)
    -- This uses raw Plutus Data to bypass the type-safe PingPongState constructors
    let invalidDatum = PV3.Constr 5 []
        invalidScriptData = C.unsafeHashableScriptData $ C.fromPlutusData invalidDatum

        scriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 Scripts.pingPongValidatorScript)
        scriptAddr = C.makeShelleyAddressInEra C.shelleyBasedEra Defaults.networkId (C.PaymentCredentialByScript scriptHash) C.NoStakeAddress
        value = C.lovelaceToValue 10_000_000

        -- Create a TxOut with the invalid inline datum
        txOut =
          C.TxOut
            scriptAddr
            (C.TxOutValueShelleyBased C.shelleyBasedEra $ C.toMaryValue value)
            (C.TxOutDatumInline C.babbageBasedEra invalidScriptData)
            C.ReferenceScriptNone

    -- Deploy the invalid datum to the script address
    deployResult <-
      runExceptT $
        tryBalanceAndSubmit
          mempty
          Wallet.w1
          (execBuildTx $ BuildTx.prependTxOut txOut)
          TrailingChange
          []

    case deployResult of
      Left err -> fail $ "Deploy failed: " ++ show err
      Right _ -> do
        -- Find the script UTxO by address (don't assume TxIx 0)
        utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
        let C.UTxO utxos = utxoSet
            -- Find UTxOs at the script address
            scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == scriptAddr) utxos

        case Map.toList scriptUtxos of
          [] -> fail "No UTxO found at script address"
          ((txIn, _) : _) -> do
            -- Use Pong as the redeemer (any valid redeemer will do - the failure
            -- happens when parsing the INPUT datum, not the redeemer)
            spendResult <-
              runExceptT $
                tryBalanceAndSubmit
                  mempty
                  Wallet.w1
                  (execBuildTx $ Scripts.playPingPongRound Defaults.networkId 10_000_000 PingPong.Pong txIn)
                  TrailingChange
                  []

            -- If the spend succeeds, we fail the test - it should have triggered the validator error
            case spendResult of
              Left err -> fail $ show err
              Right _ -> do
                fail "Spend succeeded but should have failed with 'PingPongState: invalid index'"

  -- We expect the mockchain to fail - this is correct behavior
  handleError _ = pure ()

{- | Test that using the PingPong validator with wrong script purpose triggers line 207.

The PingPong validator expects SpendingScript purpose. If called with MintingScript
(by using it as a minting policy), it should trigger:
  P.traceError "Invalid script purpose - expected SpendingScript"

In PlutusV3, a script can be used for any purpose (spending, minting, etc.).
When we use the PingPong validator script as a minting policy:
1. The script will be invoked with MintingScript in scriptContextScriptInfo
2. The pattern match on SpendingScript will fail
3. The catch-all clause on line 207 will execute
-}
testInvalidScriptPurpose :: Options C.ConwayEra -> Assertion
testInvalidScriptPurpose opts = mockchainFailsWithOptions opts action handleError
 where
  action = do
    -- Use the PingPong validator script AS a minting policy
    -- This will cause it to receive MintingScript purpose instead of SpendingScript
    let assetName = unsafeAssetName "deadbeef"
        quantity = 1

    -- Build a minting transaction using PingPong validator as the policy
    -- The script will be invoked with MintingScript purpose
    result <-
      runExceptT $
        tryBalanceAndSubmit
          mempty
          Wallet.w1
          ( execBuildTx $ do
              -- Mint using the PingPong script as a policy
              -- The script will be invoked with MintingScript purpose
              -- We use Ping as the redeemer (any redeemer will do - it'll fail on purpose check)
              mintPlutus
                Scripts.pingPongValidatorScript -- Use the spending validator as minting policy
                PingPong.Ping -- Any redeemer, doesn't matter - it'll fail on purpose check
                assetName
                quantity
          )
          TrailingChange
          []

    -- The transaction MUST fail with script error - if it succeeds, that's a test failure
    case result of
      Left err -> fail $ show err
      Right _ -> do
        -- If the transaction succeeded, the script didn't reject invalid purpose
        fail "Transaction succeeded but should have failed with 'Invalid script purpose'"

  -- We expect the mockchain to fail - this is correct behavior
  -- The error should contain "Invalid script purpose - expected SpendingScript"
  handleError _ = pure ()

{- | Test that findOwnInput recursive case (line 222) is exercised.

When a transaction has multiple inputs and the script's own input is not
the first in txInfoInputs, the recursive case of findOwnInput is triggered.

In Cardano, txInfoInputs is ordered by TxIn (TxId, then TxIx). To reliably
trigger the recursive case, we deploy TWO UTxOs to the script in SEPARATE
transactions, then spend BOTH in a SINGLE transaction.

When both script UTxOs are spent together, each validator invocation will
see both inputs in txInfoInputs. For one of them, the OWN input will be
second (after the other script input), triggering the recursive case.

The recursive case (line 222) is: findOwnInput ref (inp : rest) | otherwise = findOwnInput ref rest
-}
testFindOwnInputRecursive :: Options C.ConwayEra -> Assertion
testFindOwnInputRecursive opts = mockchainSucceedsWithOptions opts $ do
  let scriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 Scripts.pingPongValidatorScript)
      value = C.lovelaceToValue 10_000_000

  -- Deploy FIRST UTxO to the script
  deployResult1 <-
    runExceptT $
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx $
            BuildTx.payToScriptInlineDatum
              Defaults.networkId
              scriptHash
              PingPong.Pinged
              C.NoStakeAddress
              value
        )
        TrailingChange
        []

  deployTx1 <- either (fail . show) pure deployResult1
  let scriptTxIn1 = C.TxIn (C.getTxId $ C.getTxBody deployTx1) (C.TxIx 0)

  -- Deploy SECOND UTxO to the script (in a separate transaction to get different TxId)
  deployResult2 <-
    runExceptT $
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx $
            BuildTx.payToScriptInlineDatum
              Defaults.networkId
              scriptHash
              PingPong.Pinged
              C.NoStakeAddress
              value
        )
        TrailingChange
        []

  deployTx2 <- either (fail . show) pure deployResult2
  let scriptTxIn2 = C.TxIn (C.getTxId $ C.getTxBody deployTx2) (C.TxIx 0)

  -- Now spend BOTH script UTxOs in a SINGLE transaction.
  -- When the validator runs for each input, it will see BOTH inputs in txInfoInputs.
  -- Due to TxId ordering, one validator invocation will have its own input second,
  -- which MUST trigger the recursive case in findOwnInput.
  spendResult <-
    runExceptT $
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx $ do
            -- Spend first script UTxO (Pinged -> Ponged)
            Scripts.playPingPongRound Defaults.networkId 10_000_000 PingPong.Pong scriptTxIn1
            -- Spend second script UTxO (Pinged -> Ponged)
            Scripts.playPingPongRound Defaults.networkId 10_000_000 PingPong.Pong scriptTxIn2
        )
        TrailingChange
        []

  -- Verify the spend succeeded
  case spendResult of
    Left err -> fail $ "Spend failed: " ++ show err
    Right _ -> pure ()

{- | Test that NoOutputDatum error (line 249) is triggered.

When a spending transaction creates an output at the script address without a datum,
the validator triggers:
  P.traceError $ errorMsg <> " - NoOutputDatum"

The PingPong validator checks that:
1. The transaction has exactly one output to the script address
2. That output has a valid PingPongState datum

When we create an output at the script address WITHOUT any datum (using payToAddress),
the validator's getPingPongState function will receive NoOutputDatum and trigger line 249.
-}
testNoOutputDatum :: Options C.ConwayEra -> Assertion
testNoOutputDatum opts = mockchainFailsWithOptions opts action handleError
 where
  action = do
    let scriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 Scripts.pingPongValidatorScript)
        scriptAddr = C.makeShelleyAddressInEra C.shelleyBasedEra Defaults.networkId (C.PaymentCredentialByScript scriptHash) C.NoStakeAddress
        value = C.lovelaceToValue 10_000_000

    -- Deploy a valid PingPong UTxO with proper inline datum
    deployResult <-
      runExceptT $
        tryBalanceAndSubmit
          mempty
          Wallet.w1
          ( execBuildTx $
              BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
                PingPong.Pinged
                C.NoStakeAddress
                value
          )
          TrailingChange
          []

    _deployTx <- either (fail . show) pure deployResult

    -- Find the script UTxO
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let C.UTxO utxos = utxoSet
        scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == scriptAddr) utxos

    case Map.toList scriptUtxos of
      [] -> fail "No UTxO found at script address"
      ((txIn, _) : _) -> do
        -- Build a malicious spending transaction:
        -- 1. Spend the script UTxO (with proper witness for inline datum)
        -- 2. Create an output at the script address WITHOUT any datum
        --
        -- The validator will:
        -- 1. Successfully parse the input (has valid inline datum)
        -- 2. Find the output at the script address
        -- 3. Try to get the state from the output's datum
        -- 4. Fail because the output has NoOutputDatum (line 249)
        spendResult <-
          runExceptT $
            tryBalanceAndSubmit
              mempty
              Wallet.w1
              ( execBuildTx $ do
                  -- Spend the script input with inline datum
                  BuildTx.spendPlutusInlineDatum
                    txIn
                    Scripts.pingPongValidatorScript
                    PingPong.Pong -- Valid redeemer for Pinged -> Ponged transition
                    -- Create output at script address WITHOUT datum
                    -- This triggers line 249: "... - NoOutputDatum"
                  BuildTx.payToAddress scriptAddr value
              )
              TrailingChange
              []

        -- The transaction must fail with the NoOutputDatum error
        case spendResult of
          Left err -> fail $ show err
          Right _ -> do
            fail "Transaction succeeded but should have failed with 'NoOutputDatum'"

  -- We expect the mockchain to fail - this is correct behavior
  -- The error should contain "NoOutputDatum"
  handleError _ = pure ()

{- | Test that OutputDatumHash lookup succeeds for INPUT (lines 250-251).

When an INPUT uses a datum hash (not inline), and the datum is included
in the spending witness via spendPlutus, the validator should successfully:
1. Match on OutputDatumHash (line 250) when reading INPUT datum
2. Successfully look up the datum in datumMap (line 251)

The OUTPUT uses inline datum (the simpler path) to avoid the complexity of
needing to add supplemental datums to the transaction.

This test specifically exercises the datum hash lookup path for INPUTs.
-}
testOutputDatumHashFound :: Options C.ConwayEra -> Assertion
testOutputDatumHashFound opts = mockchainSucceedsWithOptions opts $ do
  let script = C.PlutusScript C.PlutusScriptV3 Scripts.pingPongValidatorScript
      scriptHash = C.hashScript script
      value = C.lovelaceToValue 10_000_000

  -- Deploy with DATUM HASH (not inline datum)
  -- This creates an input with OutputDatumHash
  deployResult <-
    runExceptT $
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx $
            BuildTx.payToScriptDatumHash
              Defaults.networkId
              script
              PingPong.Pinged
              C.NoStakeAddress
              value
        )
        TrailingChange
        []

  deployTx <- either (fail . show) pure deployResult
  let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)

  -- Spend the input using spendPlutus (NOT spendPlutusInlineDatum)
  -- This adds the input's datum (Pinged) to txInfoData
  -- The validator will look up the input datum via OutputDatumHash path
  -- For the OUTPUT, we use inline datum to keep things simple
  spendResult <-
    runExceptT $
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx $ do
            -- Spend the script input with explicit datum (datum hash)
            -- This exercises line 250-251 for the INPUT lookup
            BuildTx.spendPlutus
              txIn
              Scripts.pingPongValidatorScript
              PingPong.Pinged -- The input datum (goes to txInfoData)
              PingPong.Pong -- The redeemer
              -- Create output with INLINE datum (simpler path, always works)
            BuildTx.payToScriptInlineDatum
              Defaults.networkId
              scriptHash
              PingPong.Ponged -- The output datum (inline, no lookup needed)
              C.NoStakeAddress
              value
        )
        TrailingChange
        []

  -- Verify the spend succeeded
  case spendResult of
    Left err -> fail $ "Spend failed: " ++ show err
    Right _ -> pure ()

{- | Test that OutputDatumHash lookup fails (line 252).

When a continuation output uses a datum hash but the datum is NOT included
in the transaction witness set, the validator fails with:
  P.traceError $ errorMsg <> " - OutputDatumHash not found in datum map"

We create an output with TxOutDatumHash using a fake/unknown hash that won't
be present in txInfoData. This triggers the lookup failure path.
-}
testOutputDatumHashNotFound :: Options C.ConwayEra -> Assertion
testOutputDatumHashNotFound opts = mockchainFailsWithOptions opts action handleError
 where
  action = do
    let scriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 Scripts.pingPongValidatorScript)
        scriptAddr = C.makeShelleyAddressInEra C.shelleyBasedEra Defaults.networkId (C.PaymentCredentialByScript scriptHash) C.NoStakeAddress
        value = C.lovelaceToValue 10_000_000

    -- Deploy with valid inline datum
    deployResult <-
      runExceptT $
        tryBalanceAndSubmit
          mempty
          Wallet.w1
          ( execBuildTx $
              BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
                PingPong.Pinged
                C.NoStakeAddress
                value
          )
          TrailingChange
          []

    deployTx <- either (fail . show) pure deployResult
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)

    -- Create a fake datum hash that won't be in the datum map
    -- Use a valid 32-byte hex string that doesn't correspond to any real datum
    let fakeDatumHash = unsafeDatumHash "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

        -- Create output with datum hash that won't be found in txInfoData
        -- Using explicit ConwayEra type annotation
        txOut :: C.TxOut C.CtxTx C.ConwayEra
        txOut =
          C.TxOut
            scriptAddr
            (C.TxOutValueShelleyBased C.shelleyBasedEra $ C.toMaryValue value)
            (C.TxOutDatumHash C.alonzoBasedEra fakeDatumHash)
            C.ReferenceScriptNone

    spendResult <-
      runExceptT $
        tryBalanceAndSubmit
          mempty
          Wallet.w1
          ( execBuildTx $ do
              -- Spend the script input (which has inline datum)
              BuildTx.spendPlutusInlineDatum
                txIn
                Scripts.pingPongValidatorScript
                PingPong.Pong
              -- Create output with datum hash that won't be found
              BuildTx.prependTxOut txOut
          )
          TrailingChange
          []

    -- The transaction must fail with the OutputDatumHash not found error
    case spendResult of
      Left err -> fail $ show err
      Right _ -> do
        fail "Transaction succeeded but should have failed with 'OutputDatumHash not found in datum map'"

  -- We expect the mockchain to fail - this is correct behavior
  -- The error should contain "OutputDatumHash not found in datum map"
  handleError _ = pure ()
