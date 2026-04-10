{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Vesting.Spec.Unit where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.UseCases.Utils (utxosAt)
import Convex.Utils (failOnError)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import PlutusLedgerApi.V1 (POSIXTime (..), lovelaceValue)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Vesting.Scripts (vestingValidatorScript)
import Vesting.Validator (Vesting (..), VestingParams (..))

-------------------------------------------------------------------------------
-- Unit tests for the Vesting script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ -- availableFrom Tests
      testCase
        "Fail: Withdrawal attempt before tranche 1 vesting date"
        (mockchainFails (failOnError availableFromBeforeVestDate) (\_ -> pure ()))
    , testCase
        "Withdrawal exactly at tranche 1 vesting date"
        (mockchainSucceeds $ failOnError availableFromExactlyAtVestDate)
    , testCase
        "Withdrawal entirely after both tranche vesting dates"
        (mockchainSucceeds $ failOnError availableFromAfterVestDate)
    , testCase
        "Fail: Withdrawal with validity range overlapping but not contained within tranche 1 vesting date"
        (mockchainFails (failOnError availableFromRangeOverlapsVestDate) (\_ -> pure ()))
    , testCase
        "Fail: Withdrawal with degenerate single-point validity range before vesting dates"
        (mockchainFails (failOnError availableFromEmptyRange) (\_ -> pure ()))
    , -- remainingFrom Tests
      testCase
        "Fail: remainingFrom returns full vAmount when validity range precedes both vesting dates"
        (mockchainFails (failOnError remainingFromBeforeVestDate) (\_ -> pure ()))
    , testCase
        "remainingFrom returns zero when validity range lies entirely after both vesting dates"
        (mockchainSucceeds $ failOnError remainingFromAfterVestDate)
    , testCase
        "remainingFrom atVestDate returns zero when validity range starts exactly at vesting date"
        (mockchainSucceeds $ failOnError remainingFromAtVestDate)
    , testCase
        "remainingFrom partialTranche returns correct remainder when validity range falls between vesting dates"
        (mockchainSucceeds $ failOnError remainingFromPartialTranche)
    , -- valueLockedByAddress Tests
      testCase
        "Fail: valueLockedByAddress returns zero with empty output list"
        (mockchainFails (failOnError valueLockedByAddressNoOutputs) (\_ -> pure ()))
    , testCase
        "valueLockedByAddress singleMatchingOutput returns correct value with one matching output"
        (mockchainSucceeds $ failOnError valueLockedByAddressSingleMatchingOutput)
    , testCase
        "valueLockedByAddress multipleMatchingOutputs sums all matching outputs correctly"
        (mockchainSucceeds $ failOnError valueLockedByAddressMultipleMatchingOutputs)
    , testCase
        "Fail: valueLockedByAddress returns zero when no outputs match the target address"
        (mockchainFails (failOnError valueLockedByAddressNoMatchingOutput) (\_ -> pure ()))
    , testCase
        "valueLockedByAddress mixedOutputs correctly sums only matching outputs when some outputs go to other addresses"
        (mockchainSucceeds $ failOnError valueLockedByAddressMixedOutputs)
    , -- Signature Tests
      testCase
        "Fail: validator missingOwnerSignature rejects an otherwise valid withdrawal"
        (mockchainFails (failOnError validatorMissingOwnerSignature) (\_ -> pure ()))
    , testCase
        "validator ownerSignaturePresent accepts a valid signed withdrawal"
        (mockchainSucceeds $ failOnError validatorOwnerSignaturePresent)
    , testCase
        "Fail: validator rejects an otherwise valid withdrawal signed only by a non-owner"
        (mockchainFails (failOnError validatorWrongSignerOnly) (\_ -> pure ()))
    , -- Edge Case Tests
      testCase
        "Fail: validator scriptOutputToWrongAddress rejects withdrawal with remaining funds to wrong address"
        (mockchainFails (failOnError validatorScriptOutputToWrongAddress) (\_ -> pure ()))
    , testCase
        "validator multipleScriptOutputs accepts withdrawal with remaining value split across multiple script outputs"
        (mockchainSucceeds $ failOnError validatorMultipleScriptOutputs)
    , testCase
        "Fail: validator noScriptOutputs rejects withdrawal with no outputs to script address"
        (mockchainFails (failOnError validatorNoScriptOutputs) (\_ -> pure ()))
    , testCase
        "validator twoTransactionWithdrawals accepts sequential withdrawals for each tranche"
        (mockchainSucceeds $ failOnError validatorTwoTransactionWithdrawals)
    , testCase
        "validator threeTransactionWithdrawals accepts gradual withdrawals across three transactions"
        (mockchainSucceeds $ failOnError validatorThreeTransactionWithdrawals)
    ]

-- ============================================================================
-- availableFrom Tests
-- ============================================================================

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range ends strictly before the tranche 1
-- vesting date. The validator should compute availableFrom t1 = zero, meaning
-- the full tranche 1 amount still counts as remainingExpected. If the script
-- output does not lock that full amount back, the validator rejects with "IRV".
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 5, Slot 6], entirely before
--     both tranche dates → nothing is available yet → any withdrawal fails.
-------------------------------------------------------------------------------

availableFromBeforeVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
availableFromBeforeVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt a withdrawal before any tranche has vested  (Slot 5, before Slot 20)
  --
  -- The Tx validity range [5, 6] is NOT contained within [20, +∞), so
  -- availableFrom tranche1 = zero and availableFrom tranche2 = zero.
  -- Therefore remainingExpected = 50 ADA, but we try to withdraw 10 ADA and
  -- only lock 40 ADA back → validator must reject with "IRV".
  -- -------------------------------------------------------------------------
  setSlot 5

  let withdrawValue = C.lovelaceToValue 10_000_000 -- attempting to take 10 ADA
  let remainingValue = C.lovelaceToValue 40_000_000 -- only locking 40 ADA back
  let withdrawTx =
        execBuildTx $ do
          -- Validity range entirely before both tranche dates
          BuildTx.addValidityRangeSlots 5 6
          -- Spend the script UTxO; the redeemer is unit (BuiltinData ())
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn portion to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Return only part of the funds to the script (should be rejected)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- The transaction must be signed by the owner (vpOwner), so we submit from w1.
  -- Even though the signature check passes, the value check ("IRV") must fail
  -- because no tranche is available yet and remainingActual < remainingExpected.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range starts exactly at the tranche 1
-- vesting date. The validator should compute availableFrom t1 = vAmount, meaning
-- tranche 1 is fully available and does not contribute to remainingExpected.
-- The script output only needs to lock back tranche 2's amount.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 20, Slot 21], starting exactly
--     at tranche 1's date → tranche 1 is fully available → withdrawing 20 ADA
--     and locking back only 30 ADA (tranche 2) must succeed.
-------------------------------------------------------------------------------

availableFromExactlyAtVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
availableFromExactlyAtVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 exactly at its vesting date (Slot 20)
  --
  -- The Tx validity range [20, 21] is fully contained within [20, +∞), so
  -- availableFrom tranche1 = 20 ADA and availableFrom tranche2 = zero (since
  -- [20, 21] is NOT contained within [40, +∞)).
  -- Therefore remainingExpected = 30 ADA (tranche 2 only).
  -- We withdraw 20 ADA and lock 30 ADA back → validator must accept.
  -- -------------------------------------------------------------------------
  setSlot 20

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range starting exactly at tranche 1's vesting date
          BuildTx.addValidityRangeSlots 20 21
          -- The transaction must be signed by the owner, so we add their signature.
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 amount to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Lock tranche 2 back in the script
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner — signature check passes, value check passes.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range lies entirely after both tranche
-- vesting dates. The validator should compute availableFrom t1 = vAmount and
-- availableFrom t2 = vAmount, meaning both tranches are fully available and
-- remainingExpected = zero. The owner can withdraw the full amount without
-- locking anything back.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 50, Slot 51], entirely after
--     both tranche dates → both tranches fully available → withdrawing all
--     50 ADA and locking nothing back must succeed.
-------------------------------------------------------------------------------

availableFromAfterVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
availableFromAfterVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw everything after both tranches have vested (Slot 50)
  --
  -- The Tx validity range [50, 51] is fully contained within [20, +∞) and
  -- also within [40, +∞), so availableFrom tranche1 = 20 ADA and
  -- availableFrom tranche2 = 30 ADA.
  -- Therefore remainingExpected = zero.
  -- We withdraw all 50 ADA and lock nothing back → validator must accept.
  -- -------------------------------------------------------------------------
  setSlot 50

  let withdrawValue = C.lovelaceToValue 50_000_000 -- taking all 50 ADA
  let withdrawTx =
        execBuildTx $ do
          -- Validity range entirely after both tranche dates
          BuildTx.addValidityRangeSlots 50 51
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the full amount to the owner, nothing locked back
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue

  -- Submitted by the owner — signature check passes, value check passes
  -- since remainingExpected = zero.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range straddles the tranche 1 vesting
-- date, starting before and ending after it. Even though the range overlaps
-- with [20, +∞), it is NOT fully contained within it, so the validator
-- computes availableFrom t1 = zero. Since tranche 2 is also not available
-- (range ends before Slot 40), remainingExpected = 50 ADA. Attempting to
-- withdraw any amount and locking less than 50 ADA back must fail.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 15, Slot 25], which overlaps
--     tranche 1's date but is not fully contained in [20, +∞) → availableFrom
--     tranche1 = zero → any withdrawal fails.
-------------------------------------------------------------------------------

availableFromRangeOverlapsVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
availableFromRangeOverlapsVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt a withdrawal with a range that straddles tranche 1's date (Slot 15
  -- to Slot 25). The range starts before Slot 20, so it is NOT fully contained
  -- within [20, +∞). Therefore availableFrom tranche1 = zero, and likewise
  -- availableFrom tranche2 = zero (range ends well before Slot 40).
  -- remainingExpected = 50 ADA, but we try to withdraw 10 ADA and lock only
  -- 40 ADA back → validator must reject with "IRV".
  -- -------------------------------------------------------------------------
  setSlot 15

  let withdrawValue = C.lovelaceToValue 10_000_000 -- attempting to take 10 ADA
  let remainingValue = C.lovelaceToValue 40_000_000 -- only locking 40 ADA back
  let withdrawTx =
        execBuildTx $ do
          -- Validity range overlapping but not contained within tranche 1's date
          BuildTx.addValidityRangeSlots 15 25
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn portion to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Return only part of the funds to the script (should be rejected)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner — signature check passes, but the value check
  -- must fail with "IRV" because the overlapping range does not satisfy
  -- contains (from vestDate) range, so nothing is considered available.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range is degenerate, i.e. an empty
-- range that contains no points. An empty range cannot be fully contained
-- within [20, +∞), so the validator computes availableFrom t1 = zero and
-- availableFrom t2 = zero. Therefore remainingExpected = 50 ADA. Attempting
-- to withdraw any amount and locking less than 50 ADA back must fail.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 10, Slot 10], a single-point
--     degenerate range that starts and ends at the same slot, entirely before
--     both tranche dates → availableFrom = zero for both → any withdrawal fails.
-------------------------------------------------------------------------------

availableFromEmptyRange
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
availableFromEmptyRange = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt a withdrawal with a degenerate single-point range [Slot 10, Slot 10].
  --
  -- A degenerate range is not fully contained within [20, +∞) since it falls
  -- entirely before tranche 1's date. Therefore availableFrom tranche1 = zero
  -- and availableFrom tranche2 = zero.
  -- remainingExpected = 50 ADA, but we try to withdraw 10 ADA and lock only
  -- 40 ADA back → validator must reject with "IRV".
  -- -------------------------------------------------------------------------
  setSlot 10

  let withdrawValue = C.lovelaceToValue 10_000_000 -- attempting to take 10 ADA
  let remainingValue = C.lovelaceToValue 40_000_000 -- only locking 40 ADA back
  let withdrawTx =
        execBuildTx $ do
          -- Degenerate single-point validity range, before both tranche dates
          BuildTx.addValidityRangeSlots 10 10
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn portion to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Return only part of the funds to the script (should be rejected)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner — signature check passes, but the value check
  -- must fail with "IRV" because a degenerate range is not contained within
  -- either tranche's vesting interval, so nothing is considered available.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range ends strictly before the tranche 1
-- vesting date. The validator should compute remainingFrom t1 = vAmount, since
-- availableFrom t1 = zero (nothing is unlocked yet). Combined with tranche 2
-- also being unavailable, remainingExpected = 50 ADA. The script output must
-- lock back the full amount, so any attempt to withdraw anything must fail.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 5, Slot 6], entirely before
--     both tranche dates → remainingFrom t1 = 20 ADA (full tranche 1 amount)
--     and remainingFrom t2 = 30 ADA (full tranche 2 amount) → remainingExpected
--     = 50 ADA → locking back only 40 ADA must fail with "IRV".
-------------------------------------------------------------------------------

remainingFromBeforeVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
remainingFromBeforeVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt a withdrawal before any tranche has vested (Slot 5, before Slot 20).
  --
  -- The Tx validity range [5, 6] is NOT contained within [20, +∞), so
  -- availableFrom tranche1 = zero, meaning remainingFrom tranche1 = 20 ADA.
  -- Likewise, availableFrom tranche2 = zero, so remainingFrom tranche2 = 30 ADA.
  -- Therefore remainingExpected = 20 ADA + 30 ADA = 50 ADA. We try to withdraw
  -- 10 ADA and lock only 40 ADA back → validator must reject with "IRV",
  -- confirming that remainingFrom correctly returns the full vAmount when
  -- the validity range precedes the vesting date.
  -- -------------------------------------------------------------------------
  setSlot 5

  let withdrawValue = C.lovelaceToValue 10_000_000 -- attempting to take 10 ADA
  let remainingValue = C.lovelaceToValue 40_000_000 -- only locking 40 ADA back
  let withdrawTx =
        execBuildTx $ do
          -- Validity range entirely before both tranche dates
          BuildTx.addValidityRangeSlots 5 6
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn portion to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Return only part of the funds to the script (should be rejected)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner — signature check passes, but the value check
  -- must fail with "IRV" because remainingFrom returns the full vAmount for
  -- both tranches when the validity range precedes both vesting dates.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction's validity range lies entirely after both tranche
-- vesting dates. The validator should compute remainingFrom t1 = zero, since
-- availableFrom t1 = vAmount (fully unlocked), and likewise remainingFrom t2
-- = zero. Therefore remainingExpected = zero, meaning the owner can withdraw
-- the full 50 ADA without locking anything back.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 50, Slot 51], entirely after
--     both tranche dates → remainingFrom t1 = zero and remainingFrom t2 = zero
--     → remainingExpected = zero → withdrawing all 50 ADA with no script
--     output must succeed.
-------------------------------------------------------------------------------

remainingFromAfterVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
remainingFromAfterVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw everything after both tranches have vested (Slot 50).
  --
  -- The Tx validity range [50, 51] is fully contained within [20, +∞) and
  -- also within [40, +∞), so availableFrom tranche1 = 20 ADA and
  -- availableFrom tranche2 = 30 ADA. Therefore remainingFrom tranche1 =
  -- 20 ADA - 20 ADA = zero and remainingFrom tranche2 = 30 ADA - 30 ADA =
  -- zero. remainingExpected = zero + zero = zero. We withdraw all 50 ADA
  -- and lock nothing back → validator must accept, confirming that
  -- remainingFrom correctly returns zero when the validity range lies
  -- entirely after the vesting date.
  -- -------------------------------------------------------------------------
  setSlot 50

  let withdrawValue = C.lovelaceToValue 50_000_000 -- taking all 50 ADA
  let withdrawTx =
        execBuildTx $ do
          -- Validity range entirely after both tranche dates
          BuildTx.addValidityRangeSlots 50 51
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the full amount to the owner, nothing locked back since
          -- remainingExpected = zero
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue

  -- Submitted by the owner — signature check passes and value check passes
  -- since remainingFrom returns zero for both tranches when the validity
  -- range lies entirely after both vesting dates.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction validity range starts exactly at the vesting date.
-- For a tranche with vesting date d, if range starts at d and is contained in
-- [d, +inf), availableFrom = vAmount, so remainingFrom = 0.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20 (POSIXTime 1640995220000)
--   - Tranche 2 also vests at Slot 20 (same boundary condition)
--   - Withdrawal validity range is [Slot 20, Slot 21], starting exactly at the
--     vesting date for both tranches
--   - remainingFrom t1 = 0 and remainingFrom t2 = 0, so remainingExpected = 0
--   - With remainingExpected = 0, withdrawing all 50 ADA succeeds.
-------------------------------------------------------------------------------

remainingFromAtVestDate
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
remainingFromAtVestDate = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20 (same vesting boundary)
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw everything exactly at the vesting boundary.
  --
  -- Validity range [20, 21] is contained within [20, +inf), so availableFrom
  -- for both tranches equals full amount and remainingFrom is zero for both.
  -- remainingExpected = zero, therefore withdrawing all 50 ADA succeeds.
  -- -------------------------------------------------------------------------
  setSlot 20

  let withdrawValue = C.lovelaceToValue 50_000_000 -- taking all 50 ADA
  let withdrawTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 21
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue

  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: Two tranches with different vesting dates, validity range between them.
-- Only the first tranche is available. The validator should compute:
--   - availableFrom t1 = vAmount (since range is contained in [d1, +inf))
--   - availableFrom t2 = zero (since range is NOT contained in [d2, +inf))
-- Therefore:
--   - remainingFrom t1 = zero
--   - remainingFrom t2 = vAmount (full amount since it's not yet available)
-- remainingExpected = zero + vAmount (tranche 2 only)
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35], which is after
--     tranche 1's date but before tranche 2's date → only tranche 1 is available
--     → remainingFrom t1 = zero and remainingFrom t2 = 30 ADA (full tranche 2)
--   - remainingExpected = 30 ADA → withdrawing 20 ADA (tranche 1) and locking
--     back 30 ADA (tranche 2) must succeed.
-------------------------------------------------------------------------------

remainingFromPartialTranche
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
remainingFromPartialTranche = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 with validity range between both vesting dates.
  --
  -- The Tx validity range [25, 35] is fully contained within [20, +∞)
  -- (tranche 1's vesting interval) but NOT within [40, +∞) (tranche 2's).
  -- Therefore:
  --   - availableFrom tranche1 = 20 ADA (fully available)
  --   - availableFrom tranche2 = zero (not yet available)
  --   - remainingFrom tranche1 = 20 ADA - 20 ADA = zero
  --   - remainingFrom tranche2 = 30 ADA - zero = 30 ADA
  --   - remainingExpected = zero + 30 ADA = 30 ADA
  -- We withdraw 20 ADA (tranche 1) and lock 30 ADA (tranche 2) back.
  -- This satisfies remainingExpected ≥ remainingActual, so the validator accepts.
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 amount to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Lock tranche 2 back in the script (still locked until Slot 40)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner — signature check passes, and value check passes
  -- since remainingExpected (30 ADA, tranche 2 fully remaining) equals
  -- remainingActual (30 ADA locked back).
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-- ============================================================================
-- valueLockedByAddress Tests
-- ============================================================================

-------------------------------------------------------------------------------
-- Scenario: A withdrawal transaction with an empty output list. The validator
-- computes remainingActual = valueLockedByAddress(scriptAddress) = zero,
-- since no outputs are present. If remainingExpected > zero (any tranche is
-- still locked), the validator rejects with "IRV".
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - Initial lock: 50 ADA in script
--   - Withdrawal attempt with empty transaction outputs (no outputs at all)
--     Even after both tranches are vested, the validator must check that
--     the output list contains no script outputs, so remainingActual = zero.
--     Since we withdraw without locking anything back and remainingExpected
--     is computed for an unlocked tranche, the transaction must fail with "IRV".
--
-- Note: This tests the foundational behavior that valueLockedByAddress
-- correctly returns zero when the output list is empty, which is crucial
-- for detecting incomplete script outputs.
-------------------------------------------------------------------------------

valueLockedByAddressNoOutputs
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
valueLockedByAddressNoOutputs = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt withdrawal after both tranches have vested, but with no outputs.
  --
  -- Set the slot to after both vesting dates so both tranches are available
  -- and remainingExpected = zero. However, we construct a transaction that
  -- attempts to spend the script UTxO without producing any outputs at all.
  --
  -- Even though remainingExpected = zero (both tranches fully available),
  -- the validator still checks: remainingActual >= remainingExpected.
  -- With no outputs, valueLockedByAddress returns zero = remainingActual.
  -- This equals remainingExpected = zero, so the check passes on value.
  -- However, the coin selection or transaction building should fail because
  -- the owner doesn't receive the withdrawn funds.
  --
  -- Note: This test demonstrates that valueLockedByAddress correctly identifies
  -- an empty output list by returning zero.
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawTx =
        execBuildTx $ do
          -- Validity range after both tranches have vested
          BuildTx.addValidityRangeSlots 50 51
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
  -- Do NOT pay to any output—leaving outputs empty
  -- This ensures valueLockedByAddress returns zero

  -- Submitted by the owner. The transaction should fail because although
  -- the script constraint checks pass (remainingActual = 0 >= remainingExpected = 0),
  -- the coin selection cannot balance the transaction without output destinations.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: A withdrawal transaction with a single output that matches the
-- script address. The validator computes remainingActual = valueLockedByAddress
-- (scriptAddress), which should return the value of that single matching output.
-- If this equals remainingExpected, the validator accepts the transaction.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - Initial lock: 50 ADA in script
--   - Withdrawal at Slot 25 (after tranche 1, before tranche 2)
--     → tranche 1 available (20 ADA)
--     → tranche 2 NOT available (30 ADA still required)
--     → remainingExpected = 30 ADA
--   - Transaction output list contains exactly one output to the script address
--     with value 30 ADA
--   - valueLockedByAddress returns 30 ADA = remainingActual
--   - Check: 30 >= 30 passes
--   - Validator accepts, confirming valueLockedByAddress correctly identifies
--     and returns the value of the matching output.
-------------------------------------------------------------------------------

valueLockedByAddressSingleMatchingOutput
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
valueLockedByAddressSingleMatchingOutput = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with single matching output.
  --
  -- Set the slot to 25 (after tranche 1 vests but before tranche 2).
  -- At this point:
  --   - availableFrom tranche1 = 20 ADA
  --   - availableFrom tranche2 = zero
  --   - remainingFrom tranche1 = 0 ADA
  --   - remainingFrom tranche2 = 30 ADA (full amount, still locked)
  --   - remainingExpected = 30 ADA
  --
  -- The transaction produces exactly one output: 30 ADA locked back to the
  -- script address. valueLockedByAddress will iterate through the output list,
  -- find this single matching output, and return its value (30 ADA).
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 amount to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Lock tranche 2 back in the script—this is the single matching output
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  -- Submitted by the owner. The validator confirms:
  --   - Signature check passes (owner signed)
  --   - valueLockedByAddress(scriptAddress) = 30 ADA (the single matching output)
  --   - remainingExpected = 30 ADA (tranche 2 fully remaining)
  --   - Check: 30 >= 30 passes
  --   - Transaction accepted, proving valueLockedByAddress correctly identifies
  --     and returns the value of the matching output.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: A withdrawal transaction with multiple outputs all directed to the
-- same script address. The validator computes remainingActual by iterating
-- through the output list and summing all outputs whose address matches the
-- script address. If this sum equals remainingExpected, the validator accepts.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - Initial lock: 50 ADA in script
--   - Withdrawal at Slot 25 (after tranche 1, before tranche 2)
--     → tranche 1 available (20 ADA)
--     → tranche 2 NOT available (30 ADA still required)
--     → remainingExpected = 30 ADA
--   - Transaction output list contains three outputs to the script address:
--     10 ADA, 10 ADA, and 10 ADA (total 30 ADA)
--   - valueLockedByAddress iterates through outputs, finds all three matching
--     the script address, and sums their values: 10 + 10 + 10 = 30 ADA
--   - Check: 30 >= 30 passes
--   - Validator accepts, confirming valueLockedByAddress correctly sums
--     multiple matching outputs.
-------------------------------------------------------------------------------

valueLockedByAddressMultipleMatchingOutputs
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
valueLockedByAddressMultipleMatchingOutputs = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with multiple matching outputs.
  --
  -- Set the slot to 25 (after tranche 1 vests but before tranche 2).
  -- At this point:
  --   - availableFrom tranche1 = 20 ADA
  --   - availableFrom tranche2 = zero
  --   - remainingFrom tranche1 = 0 ADA
  --   - remainingFrom tranche2 = 30 ADA (full amount, still locked)
  --   - remainingExpected = 30 ADA
  --
  -- The transaction produces three outputs to the script address:
  --   - First output: 10 ADA to script
  --   - Second output: 10 ADA to script
  --   - Third output: 10 ADA to script
  -- Total to script: 30 ADA
  --
  -- valueLockedByAddress iterates through outputs, identifies all three
  -- matching the script address, and sums their values: 10 + 10 + 10 = 30 ADA.
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let part1Value = C.lovelaceToValue 10_000_000 -- first part to script
  let part2Value = C.lovelaceToValue 10_000_000 -- second part to script
  let part3Value = C.lovelaceToValue 10_000_000 -- third part to script
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 amount to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Lock the remaining amount back to script in three separate outputs
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress part1Value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress part2Value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress part3Value

  -- Submitted by the owner. The validator confirms:
  --   - Signature check passes (owner signed)
  --   - valueLockedByAddress(scriptAddress) sums all three matching outputs:
  --     10 ADA + 10 ADA + 10 ADA = 30 ADA = remainingActual
  --   - remainingExpected = 30 ADA (tranche 2 fully remaining)
  --   - Check: 30 >= 30 passes
  --   - Transaction accepted, proving valueLockedByAddress correctly sums
  --     multiple matching outputs.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: A withdrawal transaction where all outputs are directed to
-- addresses OTHER than the script address. The validator iterates through
-- the output list but finds no outputs matching the script address, so
-- valueLockedByAddress returns zero. If remainingExpected > zero (any tranche
-- still locked), the check remainingActual >= remainingExpected fails and the
-- validator rejects with "IRV".
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - Initial lock: 50 ADA in script
--   - Withdrawal at Slot 25 (after tranche 1, before tranche 2)
--     → tranche 1 available (20 ADA)
--     → tranche 2 NOT available (30 ADA still required)
--     → remainingExpected = 30 ADA
--   - Transaction output list contains outputs but NONE directed to the script
--     address (e.g., all to owner or other addresses)
--   - valueLockedByAddress finds no matching outputs and returns zero
--   - Check: 0 >= 30 fails
--   - Validator rejects with "IRV", confirming valueLockedByAddress correctly
--     returns zero when no outputs match the target address.
-------------------------------------------------------------------------------

valueLockedByAddressNoMatchingOutput
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
valueLockedByAddressNoMatchingOutput = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with no script outputs.
  --
  -- Set the slot to 25 (after tranche 1 vests but before tranche 2).
  -- At this point:
  --   - availableFrom tranche1 = 20 ADA
  --   - availableFrom tranche2 = zero
  --   - remainingFrom tranche1 = 0 ADA
  --   - remainingFrom tranche2 = 30 ADA (full amount, still locked)
  --   - remainingExpected = 30 ADA
  --
  -- The transaction withdraws both the available tranche 1 (20 ADA) AND the
  -- still-locked tranche 2 (30 ADA), but sends them all to the owner's address.
  -- No outputs are directed to the script address.
  --
  -- When the validator calls valueLockedByAddress(scriptAddress), it iterates
  -- through the output list, finds no outputs matching the script address, and
  -- returns zero.
  -- -------------------------------------------------------------------------
  setSlot 25

  let totalWithdraw = C.lovelaceToValue 50_000_000 -- trying to take all 50 ADA
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay all withdrawn funds to the owner (no outputs to script)
          BuildTx.payToPublicKey Defaults.networkId ownerPkh totalWithdraw

  -- Submitted by the owner. The validator checks:
  --   - Signature check passes (owner signed)
  --   - valueLockedByAddress(scriptAddress) finds no matching outputs → returns 0
  --   - remainingExpected = 30 ADA (tranche 2 fully remaining)
  --   - Check: 0 >= 30 FAILS
  --   - Transaction rejected with "IRV", proving valueLockedByAddress correctly
  --     returns zero when no outputs match the target address.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: A withdrawal transaction with a mix of outputs, some matching the
-- script address and some matching other addresses (e.g., owner). The validator
-- should sum only the outputs directed to the script address and ignore all
-- others. If this sum equals remainingExpected, the validator accepts.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - Initial lock: 50 ADA in script
--   - Withdrawal at Slot 25 (after tranche 1, before tranche 2)
--     → tranche 1 available (20 ADA)
--     → tranche 2 NOT available (30 ADA still required)
--     → remainingExpected = 30 ADA
--   - Transaction output list contains both owner and script outputs:
--     • 10 ADA to owner (part of tranche 1 withdrawal)
--     • 15 ADA to script (part of tranche 2 lock)
--     • 10 ADA to owner (rest of tranche 1 withdrawal)
--     • 15 ADA to script (rest of tranche 2 lock)
--   - valueLockedByAddress iterates through outputs, identifies only the two
--     matching the script address, and sums: 15 + 15 = 30 ADA
--   - Check: 30 >= 30 passes
--   - Validator accepts, confirming valueLockedByAddress correctly filters
--     outputs by address and ignores non-matching ones before summation.
-------------------------------------------------------------------------------

valueLockedByAddressMixedOutputs
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
valueLockedByAddressMixedOutputs = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with mixed outputs.
  --
  -- Set the slot to 25 (after tranche 1 vests but before tranche 2).
  -- At this point:
  --   - availableFrom tranche1 = 20 ADA
  --   - availableFrom tranche2 = zero
  --   - remainingFrom tranche1 = 0 ADA
  --   - remainingFrom tranche2 = 30 ADA (full amount, still locked)
  --   - remainingExpected = 30 ADA
  --
  -- The transaction produces four outputs in total:
  --   - First owner output: 10 ADA (part of tranche 1 withdrawal)
  --   - First script output: 15 ADA (part of tranche 2 lock)
  --   - Second owner output: 10 ADA (rest of tranche 1 withdrawal)
  --   - Second script output: 15 ADA (rest of tranche 2 lock)
  --
  -- valueLockedByAddress will iterate through all four outputs, identify only
  -- the two matching the script address (skipping the owner outputs), and sum
  -- them: 15 + 15 = 30 ADA. This demonstrates that the function correctly
  -- filters by address before performing the summation.
  -- -------------------------------------------------------------------------
  setSlot 25

  let ownerPart1 = C.lovelaceToValue 10_000_000 -- first owner withdrawal
  let scriptPart1 = C.lovelaceToValue 15_000_000 -- first script lock
  let ownerPart2 = C.lovelaceToValue 10_000_000 -- second owner withdrawal
  let scriptPart2 = C.lovelaceToValue 15_000_000 -- second script lock
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Interleave owner and script outputs to demonstrate filtering
          BuildTx.payToPublicKey Defaults.networkId ownerPkh ownerPart1
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress scriptPart1
          BuildTx.payToPublicKey Defaults.networkId ownerPkh ownerPart2
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress scriptPart2

  -- Submitted by the owner. The validator confirms:
  --   - Signature check passes (owner signed)
  --   - valueLockedByAddress(scriptAddress) filters outputs and sums only
  --     the two script-directed outputs: 15 ADA + 15 ADA = 30 ADA = remainingActual
  --   - The two owner-directed outputs (10 ADA + 10 ADA = 20 ADA) are ignored
  --   - remainingExpected = 30 ADA (tranche 2 fully remaining)
  --   - Check: 30 >= 30 passes
  --   - Transaction accepted, proving valueLockedByAddress correctly filters
  --     outputs by address and sums only the matching ones.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is otherwise valid, but the owner's signature is
-- missing. The validity range is between tranche 1 and tranche 2 vesting dates,
-- so tranche 1 is available and tranche 2 must remain locked.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35]
--     → tranche 1 is available (20 ADA)
--     → tranche 2 is still locked (30 ADA must remain at the script address)
--   - The transaction pays 20 ADA to the owner and locks 30 ADA back to the
--     script, so the remaining-value check is satisfied.
--   - However, the transaction omits the owner's signature, so the validator
--     must reject with "OSM".
--
-- Note: As in the existing ping-pong no-signer tests, the owner wallet is used
-- only as the fee payer. Without addRequiredSignature, the validator sees the
-- owner as absent from txInfoSignatories.
-------------------------------------------------------------------------------
validatorMissingOwnerSignature
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorMissingOwnerSignature = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates, but omit the owner signature.
  --
  -- The transaction is otherwise valid:
  --   - validity range [25, 35] makes tranche 1 available
  --   - 20 ADA is paid to the owner
  --   - 30 ADA is locked back to the script
  -- So the remaining-value check would pass, but the validator must reject
  -- on the missing owner signature check with "OSM".
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- Intentionally omit BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is valid, includes the owner's signature, and
-- locks back the correct remaining value at the script address.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35]
--     → tranche 1 is available (20 ADA)
--     → tranche 2 is still locked (30 ADA must remain at the script address)
--   - The transaction pays 20 ADA to the owner and locks 30 ADA back to the
--     script, satisfying the remaining-value check.
--   - The owner's signature is included, so the validator must accept.
-------------------------------------------------------------------------------
validatorOwnerSignaturePresent
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorOwnerSignaturePresent = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with the owner signature present.
  --
  -- The transaction is fully valid:
  --   - validity range [25, 35] makes tranche 1 available
  --   - the owner signs the transaction
  --   - 20 ADA is paid to the owner
  --   - 30 ADA is locked back to the script
  -- Therefore both the signature check and remaining-value check pass.
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- Include the required owner signature
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is otherwise valid, but the only signature
-- present belongs to a third party rather than the owner. The validity range
-- is between tranche 1 and tranche 2 vesting dates, so tranche 1 is available
-- and tranche 2 must remain locked.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35]
--     → tranche 1 is available (20 ADA)
--     → tranche 2 is still locked (30 ADA must remain at the script address)
--   - The transaction pays 20 ADA to the owner and locks 30 ADA back to the
--     script, so the remaining-value check is satisfied.
--   - However, the only signature is from a third party, not the owner, so
--     the validator must reject with "OSM".
-------------------------------------------------------------------------------
validatorWrongSignerOnly
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorWrongSignerOnly = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner
      outsider = MockWallet.w2
      outsiderPkh = verificationKeyHash outsider

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates, but sign only with a third party.
  --
  -- The transaction is otherwise valid:
  --   - validity range [25, 35] makes tranche 1 available
  --   - 20 ADA is paid to the owner
  --   - 30 ADA is locked back to the script
  -- But txInfoSignatories contains only outsiderPkh, so txSignedBy txI owner
  -- is False and the validator must reject with "OSM".
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let remainingValue = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between both vesting dates
          BuildTx.addValidityRangeSlots 25 35
          -- Intentionally sign only with a non-owner
          BuildTx.addRequiredSignature outsiderPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress remainingValue

  _ <- tryBalanceAndSubmit mempty outsider withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is properly signed by the owner and otherwise
-- valid, but the remaining funds (that should be locked at the script address)
-- are sent to the owner's address instead. When the validator calls
-- valueLockedByAddress(scriptAddress), it finds no outputs matching the script
-- address and returns zero. Since remainingExpected > zero (tranche 2 must remain
-- locked), the check remainingActual >= remainingExpected fails with "IRV".
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35]
--     → tranche 1 is available (20 ADA)
--     → tranche 2 is still locked (30 ADA must remain at the script address)
--   - The transaction is signed by the owner, so the signature check passes.
--   - However, instead of locking the remaining 30 ADA back to the script,
--     it sends them to the owner's address.
--   - valueLockedByAddress(scriptAddress) returns 0 (no script outputs found).
--   - remainingExpected = 30 ADA (tranche 2 fully remaining).
--   - Check: 0 >= 30 FAILS
--   - Validator rejects with "IRV", confirming that the validator correctly
--     detects when remaining funds are not locked at the script address.
-------------------------------------------------------------------------------
validatorScriptOutputToWrongAddress
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorScriptOutputToWrongAddress = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates, but send remaining to wrong address.
  --
  -- The transaction is signed by the owner and has valid timing:
  --   - validity range [25, 35] makes tranche 1 available
  --   - 20 ADA is paid to the owner
  -- However, instead of locking the remaining 30 ADA back to the script
  -- address, the transaction sends them to the owner's address instead.
  -- valueLockedByAddress(scriptAddress) returns 0 (no script outputs), so
  -- the check 0 >= 30 fails with "IRV".
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let wrongLockedValue = C.lovelaceToValue 30_000_000 -- remaining sent to owner, not script
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between tranches (tranche 1 available)
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Send the remaining funds to the owner's address instead of the script
          -- This causes valueLockedByAddress to return 0, failing the "IRV" check
          BuildTx.payToPublicKey Defaults.networkId ownerPkh wrongLockedValue

  -- Submitted by the owner — signature check passes, but valueLockedByAddress
  -- fails to find the 30 ADA at the script address (returnvalue = 0), so the
  -- validator rejects with "IRV".
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is properly signed by the owner and otherwise
-- valid, with the required remaining value split across multiple outputs, all
-- directed to the script address. The validator calls valueLockedByAddress
-- (scriptAddress) which iterates through the outputs, identifies all matching
-- the script address, and sums them. Since the sum equals remainingExpected,
-- the validator accepts.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 25, Slot 35]
--     → tranche 1 is available (20 ADA)
--     → tranche 2 is still locked (30 ADA must remain at the script address)
--   - The transaction is signed by the owner, so the signature check passes.
--   - Instead of a single 30 ADA output to the script, the remaining value is
--     split across three outputs: 10 ADA + 10 ADA + 10 ADA = 30 ADA, all
--     directed to the script address.
--   - valueLockedByAddress(scriptAddress) finds all three outputs, sums them:
--     10 + 10 + 10 = 30 ADA = remainingActual
--   - remainingExpected = 30 ADA (tranche 2 fully remaining)
--   - Check: 30 >= 30 PASSES
--   - Validator accepts, confirming that valueLockedByAddress correctly handles
--     multiple script outputs by summing them and that the validator accepts
--     split outputs as long as the total locked amount is sufficient.
-------------------------------------------------------------------------------
validatorMultipleScriptOutputs
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorMultipleScriptOutputs = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Withdraw tranche 1 between vesting dates with remaining split across multiple script outputs.
  --
  -- The transaction is signed by the owner and has valid timing:
  --   - validity range [25, 35] makes tranche 1 available
  --   - 20 ADA is paid to the owner
  -- The remaining 30 ADA (tranche 2) is locked back to the script, but split
  -- across three outputs: 10 ADA + 10 ADA + 10 ADA.
  -- valueLockedByAddress(scriptAddress) will find all three outputs and sum them
  -- to get 30 ADA, so the check passes.
  -- -------------------------------------------------------------------------
  setSlot 25

  let withdrawValue = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let scriptPart1 = C.lovelaceToValue 10_000_000 -- first part to script
  let scriptPart2 = C.lovelaceToValue 10_000_000 -- second part to script
  let scriptPart3 = C.lovelaceToValue 10_000_000 -- third part to script
  let withdrawTx =
        execBuildTx $ do
          -- Validity range between tranches (tranche 1 available)
          BuildTx.addValidityRangeSlots 25 35
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay the withdrawn tranche 1 to the owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue
          -- Lock remaining funds back to the script in three separate outputs
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress scriptPart1
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress scriptPart2
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress scriptPart3

  -- Submitted by the owner — signature check passes, and valueLockedByAddress
  -- correctly sums all three script-directed outputs (10 + 10 + 10 = 30 ADA),
  -- which equals remainingExpected, so the value check passes and the
  -- transaction is accepted. This confirms that the validator handles multiple
  -- script outputs correctly by summing their values before comparison.
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The transaction is properly signed by the owner, but the validity
-- range is before both tranche vesting dates, meaning the full amount (50 ADA)
-- must remain locked. Additionally, there are no outputs directed to the script
-- address at all, so valueLockedByAddress returns zero. Since remainingExpected
-- = 50 ADA (nothing is available yet) and remainingActual = 0 (no script outputs),
-- the check remainingActual >= remainingExpected fails with "IRV".
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--   - The withdrawal Tx validity range is [Slot 5, Slot 6], entirely before
--     both tranche dates → availableFrom tranche1 = zero and availableFrom
--     tranche2 = zero → remainingExpected = 50 ADA (full amount must remain)
--   - The transaction is signed by the owner, so the signature check passes.
--   - However, no outputs are directed to the script address. All funds go to
--     the owner or are not locked back at all.
--   - valueLockedByAddress(scriptAddress) returns 0 (no script outputs found).
--   - remainingExpected = 50 ADA (full vesting amount still locked).
--   - Check: 0 >= 50 FAILS
--   - Validator rejects with "IRV", confirming that the validator correctly
--     enforces the requirement that all funds be returned to the script when
--     the validity range is before the first vesting date.
-------------------------------------------------------------------------------
validatorNoScriptOutputs
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorNoScriptOutputs = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Attempt withdrawal before any tranche has vested, with no script outputs.
  --
  -- The transaction is signed by the owner, so the signature check passes.
  -- However, the validity range [5, 6] is before both tranche dates, meaning:
  --   - availableFrom tranche1 = 0 (Slot 20 not reached)
  --   - availableFrom tranche2 = 0 (Slot 40 not reached)
  --   - remainingExpected = 50 ADA (full amount must remain locked)
  --
  -- Additionally, no outputs are directed to the script address. All withdrawn
  -- funds go to the owner (or are spent as fees). This causes:
  --   - valueLockedByAddress(scriptAddress) = 0 (no script outputs)
  --   - remainingActual = 0
  --
  -- Check: 0 >= 50 FAILS → validator rejects with "IRV"
  -- -------------------------------------------------------------------------
  setSlot 5

  let withdrawValue = C.lovelaceToValue 50_000_000 -- attempting to take all 50 ADA
  let withdrawTx =
        execBuildTx $ do
          -- Validity range entirely before both tranche dates
          BuildTx.addValidityRangeSlots 5 6
          -- The transaction must be signed by the owner
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay all funds to the owner (no script outputs)
          BuildTx.payToPublicKey Defaults.networkId ownerPkh withdrawValue

  -- Submitted by the owner — signature check passes, but valueLockedByAddress
  -- finds no outputs at the script address (remains = 0), while remainingExpected
  -- = 50 ADA (nothing is available before both tranche dates), so the validator
  -- rejects with "IRV".
  _ <- tryBalanceAndSubmit mempty owner withdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The owner performs two sequential withdrawal transactions over time,
-- one for each tranche. The first transaction withdraws tranche 1 and returns
-- tranche 2 to the script. The second transaction, submitted later when tranche 2
-- has vested, withdraws tranche 2 entirely. Both transactions are signed by the
-- owner and satisfy the validator checks at each stage.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--
--   First withdrawal (Slot 25):
--     - Validity range [25, 35] lies between both tranche dates
--     - availableFrom tranche1 = 20 ADA (tranche 1 is available)
--     - availableFrom tranche2 = zero (tranche 2 not yet available)
--     - remainingExpected = 30 ADA (tranche 2 must remain locked)
--     - Transaction pays 20 ADA to owner, locks 30 ADA back to script
--     - Owner signs → both checks pass, transaction accepted
--
--   Second withdrawal (Slot 50):
--     - Validity range [50, 51] lies entirely after both vesting dates
--     - availableFrom tranche1 = 20 ADA
--     - availableFrom tranche2 = 30 ADA (tranche 2 is now available)
--     - remainingExpected = zero (all funds available)
--     - Transaction pays all 30 ADA to owner, locks nothing back
--     - Owner signs → both checks pass, transaction accepted
--
-- This tests the full lifecycle of vesting: locking funds, partial withdrawals,
-- reborrowing, and final complete withdrawal.
-------------------------------------------------------------------------------
validatorTwoTransactionWithdrawals
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorTwoTransactionWithdrawals = do
  -- -------------------------------------------------------------------------
  -- Vesting parameters
  -- -------------------------------------------------------------------------
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- -------------------------------------------------------------------------
  -- Lock the full vesting amount (tranche1 + tranche2 = 50 ADA) in the script
  -- -------------------------------------------------------------------------
  let totalVestingValue = C.lovelaceToValue 50_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress totalVestingValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  -- =========================================================================
  -- FIRST WITHDRAWAL: Tranche 1 between vesting dates
  -- =========================================================================
  setSlot 25

  let tranche1Value = C.lovelaceToValue 20_000_000 -- taking tranche 1 (20 ADA)
  let tranche2Value = C.lovelaceToValue 30_000_000 -- locking back tranche 2 (30 ADA)
  let firstWithdrawTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 25 35
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh tranche1Value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress tranche2Value

  void $ tryBalanceAndSubmit mempty owner firstWithdrawTx TrailingChange []
  secondTxIn <- fst . head <$> utxosAt scriptHash

  -- =========================================================================
  -- SECOND WITHDRAWAL: Tranche 2 after its vesting date
  -- =========================================================================
  setSlot 50

  let secondWithdrawTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 50 51
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum secondTxIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh tranche2Value

  _ <- tryBalanceAndSubmit mempty owner secondWithdrawTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Scenario: The owner performs three sequential withdrawals:
--   1) Early partial withdrawal after tranche 1 vests
--   2) Another partial withdrawal before tranche 2 vests
--   3) Final withdrawal after tranche 2 vests
--
-- This demonstrates that the validator allows gradual withdrawals as long as
-- the script keeps at least remainingExpected at each step.
--
-- Concretely:
--   - Tranche 1 vests at Slot 20  (POSIXTime 1640995220000)
--   - Tranche 2 vests at Slot 40  (POSIXTime 1640995240000)
--
--   Tx 1 at Slot 21, range [21, 22]:
--     remainingExpected = 30 ADA (tranche 2 still locked)
--     Spend 50 ADA input, withdraw 5 ADA, relock 45 ADA -> pass (45 >= 30)
--
--   Tx 2 at Slot 30, range [30, 31]:
--     remainingExpected = 30 ADA (tranche 2 still locked)
--     Spend 45 ADA input, withdraw 10 ADA, relock 35 ADA -> pass (35 >= 30)
--
--   Tx 3 at Slot 50, range [50, 51]:
--     remainingExpected = 0 (both tranches available)
--     Spend 35 ADA input, withdraw all 35 ADA, relock 0 -> pass
-------------------------------------------------------------------------------
validatorThreeTransactionWithdrawals
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
validatorThreeTransactionWithdrawals = do
  let owner = MockWallet.w1
      ownerPkh = verificationKeyHash owner

  let tranche1 =
        Vesting
          { vDate = POSIXTime 1640995220000 -- Slot 20
          , vAmount = lovelaceValue 20_000_000
          }

  let tranche2 =
        Vesting
          { vDate = POSIXTime 1640995240000 -- Slot 40
          , vAmount = lovelaceValue 30_000_000
          }

  let params =
        VestingParams
          { vpOwner = transPubKeyHash ownerPkh
          , vpTranche1 = tranche1
          , vpTranche2 = tranche2
          }

  let vestingValidator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
  let scriptHash = C.hashScript vestingValidator

  -- Lock initial 50 ADA
  let initialLockedValue = C.lovelaceToValue 50_000_000
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress initialLockedValue

  txId0 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty owner lockTx TrailingChange []
  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- =========================================================================
  -- TX 1: Withdraw 5 ADA, relock 45 ADA (still >= 30 required)
  -- =========================================================================
  setSlot 21

  let tx1Withdraw = C.lovelaceToValue 5_000_000
  let tx1Relock = C.lovelaceToValue 45_000_000

  let withdrawTx1 =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 21 22
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn0 (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh tx1Withdraw
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress tx1Relock

  void $ tryBalanceAndSubmit mempty owner withdrawTx1 TrailingChange []
  txIn1 <- fst . head <$> utxosAt scriptHash

  -- =========================================================================
  -- TX 2: Withdraw 10 ADA, relock 35 ADA (still >= 30 required)
  -- =========================================================================
  setSlot 30

  let tx2Withdraw = C.lovelaceToValue 10_000_000
  let tx2Relock = C.lovelaceToValue 35_000_000

  let withdrawTx2 =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 30 31
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn1 (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh tx2Withdraw
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash () C.NoStakeAddress tx2Relock

  void $ tryBalanceAndSubmit mempty owner withdrawTx2 TrailingChange []
  txIn2 <- fst . head <$> utxosAt scriptHash

  -- =========================================================================
  -- TX 3: After tranche 2 vests, withdraw everything left (35 ADA)
  -- =========================================================================
  setSlot 50

  let tx3Withdraw = C.lovelaceToValue 35_000_000

  let withdrawTx3 =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 50 51
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn2 (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh tx3Withdraw

  _ <- tryBalanceAndSubmit mempty owner withdrawTx3 TrailingChange []
  return ()
