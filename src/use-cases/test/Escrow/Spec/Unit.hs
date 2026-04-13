{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Escrow.Spec.Unit where

import Cardano.Api qualified as C
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash, transScriptHash)
import Convex.Utils (failOnError)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Escrow.Scripts (escrowValidatorScript)
import Escrow.Validator (
  Action (..),
  EscrowParams (..),
  EscrowTarget (..),
 )
import PlutusLedgerApi.V1 (Datum (Datum), POSIXTime (..), ToData (toBuiltinData), lovelaceValue)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

-------------------------------------------------------------------------------
-- Unit tests for the Escrow script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ -- Redeem test cases
      testCase
        "Redeem succeeds when all PKH targets are met and tx is before deadline"
        (mockchainSucceeds $ failOnError redeemAllPkhTargetsMetTest)
    , testCase
        "Redeem succeeds when all Script targets are met with correct inline datum and value"
        (mockchainSucceeds $ failOnError redeemScriptTargetsMetTest)
    , testCase
        "Redeem succeeds with mixed targets (PKH + Script)"
        (mockchainSucceeds $ failOnError redeemMixedTargetsTest)
    , testCase
        "Redeem succeeds when a target is overpaid (geq allows excess)"
        (mockchainSucceeds $ failOnError redeemPkhTargetOverpaidTest)
    , -- Failing Redeem test cases
      testCase
        "Redeem fails when valid range extends past deadline"
        (mockchainFails (failOnError redeemFailsWhenRangePastDeadlineTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when a PKH target is underpaid"
        (mockchainFails (failOnError redeemFailsWhenPkhTargetUnderpaidTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when a PKH target output is missing entirely"
        (mockchainFails (failOnError redeemFailsWhenPkhTargetMissingTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when a Script target carries the wrong inline datum"
        (mockchainFails (failOnError redeemFailsWhenScriptTargetWrongDatumTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when a Script target output uses a datum hash instead of inline datum"
        (mockchainFails (failOnError redeemFailsWhenScriptTargetDatumHashTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when a Script target output is missing entirely"
        (mockchainFails (failOnError redeemFailsWhenScriptTargetMissingTest) (\_ -> pure ()))
    , testCase
        "Redeem fails when only one of two targets is satisfied"
        (mockchainFails (failOnError redeemFailsWhenOneOfTwoTargetsMissingTest) (\_ -> pure ()))
    , -- Refund test cases
      testCase
        "Refund succeeds when deadline has passed and contributor signs"
        (mockchainSucceeds $ failOnError refundSucceedsAfterDeadlineTest)
    , testCase
        "Refund succeeds independently per contributor datum at the same script"
        (mockchainSucceeds $ failOnError refundSucceedsPerContributorDatumTest)
    , -- Failing Refund test cases
      testCase
        "Refund fails when deadline has not yet passed"
        (mockchainFails (failOnError refundFailsBeforeDeadlineTest) (\_ -> pure ()))
    , testCase
        "Refund fails when deadline has passed but contributor did not sign"
        (mockchainFails (failOnError refundFailsWithoutContributorSignatureTest) (\_ -> pure ()))
    , testCase
        "Refund fails when a different PKH signs (not the contributor)"
        (mockchainFails (failOnError refundFailsWhenDifferentSignerTest) (\_ -> pure ()))
    , -- Edge cases
      testCase
        "Redeem succeeds when validity upper bound is exactly the deadline"
        (mockchainSucceeds $ failOnError redeemAtDeadlineBoundaryTest)
    , testCase
        "Refund succeeds when validity lower bound is exactly the deadline"
        (mockchainSucceeds $ failOnError refundAtDeadlineLowerBoundTest)
    , testCase
        "Redeem succeeds when targets list is empty (vacuous truth)"
        (mockchainSucceeds $ failOnError redeemSucceedsWithEmptyTargetsTest)
    , testCase
        "Refund succeeds when two script inputs are refunded in one tx with both contributor signatures"
        (mockchainSucceeds $ failOnError refundTwoInputsSameTxSucceedsTest)
    , -- General / Context Failures
      testCase
        "Fails when Escrow is used as a minting script (non-spending context)"
        (mockchainFails (failOnError escrowFailsWhenUsedAsMintingScriptTest) (\_ -> pure ()))
    , testCase
        "Fails with malformed redeemer (cannot decode to Redeem/Refund)"
        (mockchainFails (failOnError malformedRedeemerFailsTest) (\_ -> pure ()))
    ]

-- ============================================================================
-- Redeem Redeemer Tests
-- ============================================================================

-------------------------------------------------------------------------------
-- redeemAllPkhTargetsMetTest
--
-- Scenario:
--   - Two PKH targets: wallet 2 must receive 10 ADA, wallet 3 must receive 5 ADA
--   - Contributor (wallet 1) locks 15 ADA at the script with their PKH as inline datum
--   - Redeem tx validity range is [slot 5, slot 9], fully within the deadline (slot 10)
--   - Both target outputs are included with exactly the required values
--   - Expected: validator accepts the transaction
-------------------------------------------------------------------------------

redeemAllPkhTargetsMetTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemAllPkhTargetsMetTest = do
  -- Wallets:
  --   w1 = contributor (locks the funds)
  --   w2 = first target recipient (10 ADA)
  --   w3 = second target recipient (5 ADA)
  let contributor = MockWallet.w1
      target1Wallet = MockWallet.w2
      target2Wallet = MockWallet.w3

  let target1Pkh = transPubKeyHash $ verificationKeyHash target1Wallet
      target2Pkh = transPubKeyHash $ verificationKeyHash target2Wallet
      contributorPkh = transPubKeyHash $ verificationKeyHash contributor

  -- Define escrow parameters:
  --   deadline = POSIXTime 1640995210000  (Slot 10)
  --   targets  = [ pay 10 ADA to w2, pay 5 ADA to w3 ]
  let target1Value = lovelaceValue 10_000_000
      target2Value = lovelaceValue 5_000_000

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets =
              [ PaymentPubKeyTarget target1Pkh target1Value
              , PaymentPubKeyTarget target2Pkh target2Value
              ]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  ---------------------------------------------------------------------------
  -- Step 1: Contributor (w1) locks 15 ADA at the script
  --         Inline datum = contributor's PubKeyHash
  ---------------------------------------------------------------------------

  -- The locked value must cover both targets
  let lockedValue = C.lovelaceToValue 15_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh -- inline datum: contributor's PKH
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  ---------------------------------------------------------------------------
  -- Step 2: Redeem — spend the script UTxO, paying each target their required value
  --         Validity range: [slot 5, slot 9] — fully before deadline (slot 10)
  ---------------------------------------------------------------------------

  setSlot 5

  let redeemTx =
        execBuildTx $ do
          -- Validity range fully within `to deadline` (slots 5–9 < slot 10)
          BuildTx.addValidityRangeSlots 5 9
          -- Spend the script UTxO with Redeem redeemer
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- Pay target 1: wallet 2 receives 10 ADA
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId target1Wallet)
            (C.lovelaceToValue 10_000_000)
          -- Pay target 2: wallet 3 receives 5 ADA
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId target2Wallet)
            (C.lovelaceToValue 5_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemScriptTargetsMetTest
--
-- Scenario:
--   - One ScriptTarget: a second escrow instance acts as the target script.
--     It must receive 10 ADA with a specific inline datum (contributor's PKH).
--   - Contributor (wallet 1) locks 10 ADA at the main escrow with their PKH
--     as inline datum.
--   - Redeem tx validity range is [slot 5, slot 9], fully before deadline (slot 10).
--   - The output to the target script carries the correct inline datum and value.
--   - Expected: validator accepts the transaction.
--
-- Note on the target script choice: we use a second EscrowParams instance
-- purely to have a real on-chain script hash to pay into. The escrow validator
-- only cares about the hash, the inline datum content, and the value — it does
-- not matter what the target script's own logic does.
-------------------------------------------------------------------------------

redeemScriptTargetsMetTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemScriptTargetsMetTest = do
  let contributor = MockWallet.w1
      contributorPkh = transPubKeyHash $ verificationKeyHash contributor

  ---------------------------------------------------------------------------
  -- Build the target script - a second escrow instance used purely as a
  -- known script address to pay into
  ---------------------------------------------------------------------------

  let targetScriptParams =
        EscrowParams
          { epDeadline = POSIXTime 1640995230000 -- different deadline, irrelevant
          , epTargets = []
          }

  let targetCScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript targetScriptParams)
      targetHashC = C.hashScript targetCScript -- Cardano.Api ScriptHash
      targetHash = transScriptHash targetHashC -- Plutus ScriptHash

  -- The inline datum the target output must carry.
  -- We use the contributor's PKH — a meaningful value since the target is
  -- itself an escrow that expects a contributor PKH as its datum.
  let targetDatum = Datum (toBuiltinData contributorPkh)
  let targetValue = lovelaceValue 10_000_000

  ---------------------------------------------------------------------------
  -- Define the main escrow being tested, with one ScriptTarget
  ---------------------------------------------------------------------------

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [ScriptTarget targetHash targetDatum targetValue]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  ---------------------------------------------------------------------------
  -- Step 1: Contributor (w1) locks 10 ADA at the main escrow script
  --         Inline datum = contributor's PubKeyHash
  ---------------------------------------------------------------------------

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh -- inline datum: contributor's PKH
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  ---------------------------------------------------------------------------
  -- Step 2: Redeem — spend the main escrow UTxO, paying the target script
  --         the required 10 ADA with the correct inline datum
  --         Validity range: [slot 5, slot 9] — fully before deadline (slot 10)
  ---------------------------------------------------------------------------

  setSlot 5

  let redeemTx =
        execBuildTx $ do
          -- Validity range fully within `to deadline` (slots 5–9 < slot 10)
          BuildTx.addValidityRangeSlots 5 9
          -- Spend the main escrow UTxO with Redeem redeemer
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- Pay the target script: correct hash, correct inline datum, correct value
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            targetHashC
            contributorPkh -- inline datum must match targetDatum exactly
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemMixedTargetsTest
--
-- Scenario:
--   - Two targets: one PaymentPubKeyTarget (w2 receives 8 ADA) and one
--     ScriptTarget (a second escrow instance receives 7 ADA with the
--     contributor's PKH as inline datum)
--   - Contributor (w1) locks 15 ADA at the main escrow with their PKH as
--     inline datum
--   - Redeem tx validity range is [slot 5, slot 9], fully before deadline (slot 10)
--   - Both outputs are produced in the same tx: one to w2's address, one to
--     the target script with the correct datum and value
--   - Expected: validator accepts the transaction
-------------------------------------------------------------------------------

redeemMixedTargetsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemMixedTargetsTest = do
  -- Wallets:
  --   w1 = contributor (locks the funds)
  --   w2 = PKH target recipient (8 ADA)
  let contributor = MockWallet.w1
      pkhTargetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      pkhTargetPkh = transPubKeyHash $ verificationKeyHash pkhTargetWallet

  ---------------------------------------------------------------------------
  -- Build the script target — a second escrow instance used as the
  -- destination script address
  ---------------------------------------------------------------------------

  let targetScriptParams =
        EscrowParams
          { epDeadline = POSIXTime 1640995230000 -- different deadline, irrelevant
          , epTargets = []
          }

  let targetCScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript targetScriptParams)
      targetHashC = C.hashScript targetCScript -- Cardano.Api ScriptHash
      targetHash = transScriptHash targetHashC -- Plutus ScriptHash

  -- The inline datum the target script output must carry.
  -- We use the contributor's PKH — a realistic value since the target is
  -- itself an escrow expecting a contributor PKH as its datum.
  let targetDatum = Datum (toBuiltinData contributorPkh)

  ---------------------------------------------------------------------------
  -- Define the main escrow being tested, with one PKH target + one ScriptTarget
  ---------------------------------------------------------------------------

  let pkhTargetValue = lovelaceValue 8_000_000
      scriptTargetValue = lovelaceValue 7_000_000

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets =
              [ PaymentPubKeyTarget pkhTargetPkh pkhTargetValue
              , ScriptTarget targetHash targetDatum scriptTargetValue
              ]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  ---------------------------------------------------------------------------
  -- Step 1: Contributor (w1) locks 15 ADA at the main escrow
  --         Inline datum = contributor's PubKeyHash
  ---------------------------------------------------------------------------

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 15_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  ---------------------------------------------------------------------------
  -- Step 2: Redeem — produce both outputs in the same tx:
  --           • 8 ADA to w2's address  (satisfies PaymentPubKeyTarget)
  --           • 7 ADA to the target script with contributorPkh as inline datum
  --             (satisfies ScriptTarget)
  --         Validity range: [slot 5, slot 9] — fully before deadline (slot 10)
  ---------------------------------------------------------------------------

  setSlot 5

  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          -- Spend the main escrow UTxO with Redeem redeemer
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- Satisfy the PaymentPubKeyTarget: pay w2 exactly 8 ADA
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId pkhTargetWallet)
            (C.lovelaceToValue 8_000_000)
          -- Satisfy the ScriptTarget: pay the target script 7 ADA with the
          -- correct inline datum (contributorPkh, matching targetDatum)
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            targetHashC
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 7_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemPkhTargetOverpaidTest
--
-- Scenario:
--   - One PKH target requires 10 ADA to wallet 2
--   - Contributor (wallet 1) locks 12 ADA at escrow
--   - Redeem pays 12 ADA to wallet 2 (overpay)
--   - Expected: validator accepts, since target checks use geq (not equality)
-------------------------------------------------------------------------------
redeemPkhTargetOverpaidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemPkhTargetOverpaidTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let requiredTargetValue = lovelaceValue 10_000_000
      paidTargetValue = C.lovelaceToValue 12_000_000

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh requiredTargetValue]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock 12 ADA at the escrow
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 12_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem before deadline and overpay target (12 ADA > required 10 ADA)
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId targetWallet)
            paidTargetValue

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenRangePastDeadlineTest
--
-- Scenario:
--   - One PKH target requires 10 ADA to wallet 2
--   - Contributor locks 10 ADA at escrow
--   - Redeem attempts validity range [slot 5, slot 11]
--   - Deadline is slot 10, so upper bound extends past deadline
--   - Expected: validator rejects with deadline check (DLP branch)
-------------------------------------------------------------------------------
redeemFailsWhenRangePastDeadlineTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenRangePastDeadlineTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  let redeemTx =
        execBuildTx $ do
          -- This upper bound exceeds deadline (slot 10), so Redeem must fail
          BuildTx.addValidityRangeSlots 5 11
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId targetWallet)
            (C.lovelaceToValue 10_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenPkhTargetUnderpaidTest
--
-- Scenario:
--   - One PKH target requires 10 ADA to wallet 2
--   - Contributor locks 10 ADA at escrow
--   - Redeem sends only 9 ADA to wallet 2
--   - Target output exists, but value is insufficient
--   - Expected: validator rejects in target check (TGT path)
-------------------------------------------------------------------------------
redeemFailsWhenPkhTargetUnderpaidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenPkhTargetUnderpaidTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let requiredTargetValue = lovelaceValue 10_000_000

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh requiredTargetValue]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  let redeemTx =
        execBuildTx $ do
          -- Keep range valid so failure is specifically due to underpayment
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- Output exists for target PKH, but is below the required 10 ADA
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId targetWallet)
            (C.lovelaceToValue 9_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenPkhTargetMissingTest
--
-- Scenario:
--   - One PKH target requires 10 ADA to wallet 2
--   - Contributor locks 10 ADA at escrow
--   - Redeem produces no output to wallet 2 at all
--   - valuePaidToPkh returns zero, failing geq against the required value
--   - Expected: validator rejects in target check (TGT branch)
-------------------------------------------------------------------------------
redeemFailsWhenPkhTargetMissingTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenPkhTargetMissingTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem with a valid time range but no output to the target PKH.
  -- The unlocked funds return to the contributor via trailing change.
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenScriptTargetWrongDatumTest
--
-- Scenario:
--   - One ScriptTarget expects 10 ADA at the target script with
--     contributorPkh as the inline datum
--   - Redeem produces an output at the correct script address with enough
--     value, but uses a different wallet's PKH as the inline datum
--   - Datum equality check (d == getDatum dat) fails, value is irrelevant
--   - Expected: validator rejects in target check (TGT branch)
-------------------------------------------------------------------------------
redeemFailsWhenScriptTargetWrongDatumTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenScriptTargetWrongDatumTest = do
  let contributor = MockWallet.w1
      wrongDatumWallet = MockWallet.w3 -- w3's PKH will be the wrong datum
  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      wrongDatumPkh = transPubKeyHash $ verificationKeyHash wrongDatumWallet

  ---------------------------------------------------------------------------
  -- Build the target script — a second escrow instance used as the
  -- destination script address
  ---------------------------------------------------------------------------

  let targetScriptParams =
        EscrowParams
          { epDeadline = POSIXTime 1640995230000
          , epTargets = []
          }

  let targetCScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript targetScriptParams)
      targetHashC = C.hashScript targetCScript
      targetHash = transScriptHash targetHashC

  -- The datum the validator expects at the target output
  let expectedDatum = Datum (toBuiltinData contributorPkh)

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [ScriptTarget targetHash expectedDatum (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem: correct script address, sufficient value, but wrong inline datum
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- w3's PKH as datum instead of the expected contributorPkh
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            targetHashC
            wrongDatumPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenScriptTargetDatumHashTest
--
-- Scenario:
--   - One ScriptTarget expects 10 ADA at the target script with
--     contributorPkh as an inline datum
--   - Redeem produces an output at the correct script address with enough
--     value, but attaches the datum as a datum hash (TxOutDatumHash)
--     instead of an inline datum
--   - On-chain OutputDatum pattern doesn't match; falls through to
--     `_ -> traceError "WDT"` (wrong datum type)
--   - Expected: validator rejects in target check (WDT branch)
-------------------------------------------------------------------------------
redeemFailsWhenScriptTargetDatumHashTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenScriptTargetDatumHashTest = do
  let contributor = MockWallet.w1

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor

  ---------------------------------------------------------------------------
  -- Build the target script — a second escrow instance used as the
  -- destination script address
  ---------------------------------------------------------------------------

  let targetScriptParams =
        EscrowParams
          { epDeadline = POSIXTime 1640995230000
          , epTargets = []
          }

  let targetCScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript targetScriptParams)
      targetHashC = C.hashScript targetCScript
      targetHash = transScriptHash targetHashC

  let expectedDatum = Datum (toBuiltinData contributorPkh)

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [ScriptTarget targetHash expectedDatum (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem: correct script address, sufficient value, but datum is hashed
  -- rather than inline — hits the `_ -> traceError "WDT"` branch
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          BuildTx.payToScriptDatumHash
            Defaults.networkId
            targetCScript
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenScriptTargetMissingTest
--
-- Scenario:
--   - One ScriptTarget requires 10 ADA at the target script with
--     contributorPkh as inline datum
--   - Redeem produces no output to the target script address at all
--   - scriptOutputAt returns Nothing, hitting traceError "SNF"
--   - Expected: validator rejects in target check (SNF branch)
-------------------------------------------------------------------------------
redeemFailsWhenScriptTargetMissingTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenScriptTargetMissingTest = do
  let contributor = MockWallet.w1

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor

  ---------------------------------------------------------------------------
  -- Build the target script — a second escrow instance used as the
  -- destination script address
  ---------------------------------------------------------------------------

  let targetScriptParams =
        EscrowParams
          { epDeadline = POSIXTime 1640995230000
          , epTargets = []
          }

  let targetCScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript targetScriptParams)
      targetHashC = C.hashScript targetCScript
      targetHash = transScriptHash targetHashC

  let expectedDatum = Datum (toBuiltinData contributorPkh)

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [ScriptTarget targetHash expectedDatum (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem: no output to the target script address at all.
  -- The unlocked funds return to the contributor via trailing change.
  -- scriptOutputAt finds no matching output → traceError "SNF".
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemFailsWhenOneOfTwoTargetsMissingTest
--
-- Scenario:
--   - Two PKH targets: w2 requires 8 ADA, w3 requires 7 ADA
--   - Contributor locks 15 ADA at the escrow
--   - Redeem pays w2 its required 8 ADA but produces no output to w3
--   - all (meetsTarget txI) targets evaluates the w3 target to False
--   - Expected: validator rejects in target check (TGT branch)
-------------------------------------------------------------------------------
redeemFailsWhenOneOfTwoTargetsMissingTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemFailsWhenOneOfTwoTargetsMissingTest = do
  let contributor = MockWallet.w1
      target1Wallet = MockWallet.w2
      target2Wallet = MockWallet.w3

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      target1Pkh = transPubKeyHash $ verificationKeyHash target1Wallet
      target2Pkh = transPubKeyHash $ verificationKeyHash target2Wallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets =
              [ PaymentPubKeyTarget target1Pkh (lovelaceValue 8_000_000)
              , PaymentPubKeyTarget target2Pkh (lovelaceValue 7_000_000)
              ]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 15_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem: w2 is paid correctly, but w3 receives nothing.
  -- The second target fails, so all targets check fails → TGT.
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- First target satisfied
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId target1Wallet)
            (C.lovelaceToValue 8_000_000)
  -- Second target intentionally omitted

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []
  return ()

-------------------------------------------------------------------------------
-- refundSucceedsAfterDeadlineTest
--
-- Scenario:
--   - One PKH target (irrelevant for Refund path, but params must be valid)
--   - Contributor (w1) locks 10 ADA at the escrow with their PKH as inline datum
--   - Validity range is [slot 11, slot 15]: lower bound maps to POSIXTime
--     strictly greater than deadline - 1, satisfying the `before` check
--   - Transaction is signed by the contributor (tryBalanceAndSubmit adds the sig)
--   - Expected: validator accepts via the Refund branch (otherwise -> True)
-------------------------------------------------------------------------------
refundSucceedsAfterDeadlineTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundSucceedsAfterDeadlineTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      contributorPkhC = verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- Advance past deadline (slot 10)
  setSlot 11

  -- Refund: lower bound slot 11 > deadline slot 10, so
  -- (deadline - 1) `before` validRange holds.
  -- Contributor signs via tryBalanceAndSubmit, satisfying txSignedBy check.
  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          BuildTx.addRequiredSignature contributorPkhC
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor refundTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundSucceedsPerContributorDatumTest
--
-- Scenario:
--   - Two contributors (w1, w2) lock separate UTxOs at the same escrow script
--   - Each UTxO has its own contributor PKH in inline datum
--   - After deadline, each UTxO is refunded in a separate tx signed by its own contributor
--   - Expected: both refunds succeed
-------------------------------------------------------------------------------
refundSucceedsPerContributorDatumTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundSucceedsPerContributorDatumTest = do
  let contributor1 = MockWallet.w1
      contributor2 = MockWallet.w2
      targetWallet = MockWallet.w3

  let contributor1Pkh = transPubKeyHash $ verificationKeyHash contributor1
      contributor2Pkh = transPubKeyHash $ verificationKeyHash contributor2
      contributor1PkhC = verificationKeyHash contributor1
      contributor2PkhC = verificationKeyHash contributor2
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 5_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock UTxO #1 from contributor1
  let lockTx1 =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributor1Pkh
            C.NoStakeAddress
            (C.lovelaceToValue 8_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor1 lockTx1 TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- Lock UTxO #2 from contributor2 (same script, different datum)
  let lockTx2 =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributor2Pkh
            C.NoStakeAddress
            (C.lovelaceToValue 9_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor2 lockTx2 TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- Move past deadline
  setSlot 11

  -- Refund UTxO #1: must be signed by contributor1
  let refundTx1 =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          BuildTx.addRequiredSignature contributor1PkhC
          BuildTx.spendPlutusInlineDatum txIn1 (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor1 refundTx1 TrailingChange []

  -- Refund UTxO #2: must be signed by contributor2
  let refundTx2 =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          BuildTx.addRequiredSignature contributor2PkhC
          BuildTx.spendPlutusInlineDatum txIn2 (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor2 refundTx2 TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundFailsBeforeDeadlineTest
--
-- Scenario:
--   - Contributor locks 10 ADA at the escrow with their PKH as inline datum
--   - Refund tx validity range is entirely before deadline (slots 5..9, deadline slot 10)
--   - Expected: validator rejects in Refund branch with DNP
-------------------------------------------------------------------------------
refundFailsBeforeDeadlineTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundFailsBeforeDeadlineTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      contributorPkhC = verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Entirely before deadline: should fail DNP
  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.addRequiredSignature contributorPkhC
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor refundTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundFailsWithoutContributorSignatureTest
--
-- Scenario:
--   - Contributor (w1) locks funds at escrow with their PKH in inline datum
--   - Refund is attempted after deadline (time condition satisfied)
--   - Tx does NOT include contributor as required signer
--   - Expected: validator rejects with SNS
-------------------------------------------------------------------------------
refundFailsWithoutContributorSignatureTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundFailsWithoutContributorSignatureTest = do
  let contributor = MockWallet.w1
      attacker = MockWallet.w2
      targetWallet = MockWallet.w3

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock by contributor (w1), so datum contributor is w1
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- Past deadline so DNP should pass; failure should be SNS only
  setSlot 11

  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          -- Intentionally DO NOT add:
          -- BuildTx.addRequiredSignature (verificationKeyHash contributor)
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  -- Submit from a different wallet; contributor signature remains absent
  _ <- tryBalanceAndSubmit mempty attacker refundTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundFailsWhenDifferentSignerTest
--
-- Scenario:
--   - Contributor (w1) locks funds with their PKH as inline datum
--   - Refund is attempted after deadline (time check passes)
--   - A different wallet (w3) is explicitly added as required signer
--   - Contributor is NOT in signatories
--   - Expected: validator rejects with SNS
-------------------------------------------------------------------------------
refundFailsWhenDifferentSignerTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundFailsWhenDifferentSignerTest = do
  let contributor = MockWallet.w1
      signer = MockWallet.w3
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      signerPkhC = verificationKeyHash signer
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock by contributor (datum contributor = w1)
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- Past deadline: DNP condition should pass
  setSlot 11

  -- Add only a third-party signer, not the contributor
  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          BuildTx.addRequiredSignature signerPkhC
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty signer refundTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemAtDeadlineBoundaryTest
--
-- Scenario:
--   - One PKH target requires 10 ADA to wallet 2
--   - Contributor locks 10 ADA at escrow
--   - Redeem validity range upper bound is exactly slot 10 (deadline)
--   - Expected: validator accepts, because `to deadline` is inclusive
-------------------------------------------------------------------------------
redeemAtDeadlineBoundaryTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemAtDeadlineBoundaryTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Upper bound exactly equals deadline slot
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 10
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId targetWallet)
            (C.lovelaceToValue 10_000_000)

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundAtDeadlineLowerBoundTest
--
-- Scenario:
--   - Contributor locks 10 ADA at escrow with their PKH as inline datum
--   - Refund validity lower bound is exactly deadline slot (10)
--   - Since validator checks (deadline - 1) `before` validRange, this should pass
--   - Contributor signature is included
--   - Expected: validator accepts
-------------------------------------------------------------------------------
refundAtDeadlineLowerBoundTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundAtDeadlineLowerBoundTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      contributorPkhC = verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 10_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- At deadline boundary
  setSlot 10

  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 10 12
          BuildTx.addRequiredSignature contributorPkhC
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor refundTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- redeemSucceedsWithEmptyTargetsTest
--
-- Scenario:
--   - Escrow has no targets: epTargets = []
--   - Contributor locks funds at the script with contributor PKH as datum
--   - Redeem occurs before deadline
--   - Expected: validator accepts because all (meetsTarget txI) [] is True
-------------------------------------------------------------------------------
redeemSucceedsWithEmptyTargetsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
redeemSucceedsWithEmptyTargetsTest = do
  let contributor = MockWallet.w1
  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = []
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock some value at script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 5_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  -- Redeem before deadline with no required target outputs
  let redeemTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem

  _ <- tryBalanceAndSubmit mempty contributor redeemTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- refundTwoInputsSameTxSucceedsTest
--
-- Scenario:
--   - Two UTxOs are locked at the same validator with different contributor datums
--     (w1 and w2)
--   - One refund transaction spends both script inputs
--   - Tx includes both contributor signatures
--   - Expected: succeeds, demonstrating validator runs per input and each datum's
--     signer condition is checked independently
-------------------------------------------------------------------------------
refundTwoInputsSameTxSucceedsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
refundTwoInputsSameTxSucceedsTest = do
  let contributor1 = MockWallet.w1
      contributor2 = MockWallet.w2
      targetWallet = MockWallet.w3

  let contributor1Pkh = transPubKeyHash $ verificationKeyHash contributor1
      contributor2Pkh = transPubKeyHash $ verificationKeyHash contributor2
      contributor1PkhC = verificationKeyHash contributor1
      contributor2PkhC = verificationKeyHash contributor2
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000 -- Slot 10
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 5_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Lock UTxO 1 with contributor datum = w1
  let lockTx1 =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributor1Pkh
            C.NoStakeAddress
            (C.lovelaceToValue 8_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor1 lockTx1 TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- Lock UTxO 2 with contributor datum = w2
  let lockTx2 =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributor2Pkh
            C.NoStakeAddress
            (C.lovelaceToValue 9_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor2 lockTx2 TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- Past deadline so Refund path time condition is satisfied
  setSlot 11

  -- One tx spends both script inputs; both contributor signatures are present
  let refundTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 11 15
          BuildTx.addRequiredSignature contributor1PkhC
          BuildTx.addRequiredSignature contributor2PkhC
          BuildTx.spendPlutusInlineDatum txIn1 (escrowValidatorScript params) Refund
          BuildTx.spendPlutusInlineDatum txIn2 (escrowValidatorScript params) Refund

  _ <- tryBalanceAndSubmit mempty contributor1 refundTx TrailingChange [C.WitnessPaymentKey (MockWallet.getWallet contributor2)]

  return ()

----------------------------------------------------------------------------
-- escrowFailsWhenUsedAsMintingScriptTest
--
-- Scenario:
--   - Escrow validator is incorrectly used as a minting script
--   - Script purpose in ScriptContext is MintingScript, not SpendingScript
--   - Expected: validation fails at contributor extraction branch
----------------------------------------------------------------------------
escrowFailsWhenUsedAsMintingScriptTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
escrowFailsWhenUsedAsMintingScriptTest = do
  let submitter = MockWallet.w1
      targetWallet = MockWallet.w2

  let targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 1_000_000)]
          }

  -- Intentionally wrong usage: escrow validator as minting policy script
  let badMintTx =
        execBuildTx $
          BuildTx.mintPlutus
            (escrowValidatorScript params)
            Redeem
            (C.UnsafeAssetName "ESCROW_BAD_PURPOSE")
            1

  _ <- tryBalanceAndSubmit mempty submitter badMintTx TrailingChange []

  return ()

---------------------------------------------------------------------------
-- malformedRedeemerFailsTest
--
-- Scenario:
--   - Spend escrow UTxO with a redeemer that is not Action-encoded data
--   - Expected: validator fails during Action decode
---------------------------------------------------------------------------
malformedRedeemerFailsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
malformedRedeemerFailsTest = do
  let contributor = MockWallet.w1
      targetWallet = MockWallet.w2

  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
      targetPkh = transPubKeyHash $ verificationKeyHash targetWallet

  let params =
        EscrowParams
          { epDeadline = POSIXTime 1640995210000
          , epTargets = [PaymentPubKeyTarget targetPkh (lovelaceValue 1_000_000)]
          }

  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            (C.lovelaceToValue 2_000_000)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty contributor lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  setSlot 5

  let badRedeemerTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 5 9
          BuildTx.spendPlutusInlineDatum
            txIn
            (escrowValidatorScript params)
            (42 :: Integer)

  _ <- tryBalanceAndSubmit mempty contributor badRedeemerTx TrailingChange []

  return ()
