{-# LANGUAGE TypeApplications #-}

module Vesting.Spec.Unit (
  unitTests,
) where

import Control.Monad (void)
import Control.Monad.Except (MonadError)

import Cardano.Api qualified as C
import Convex.Class (
  MonadMockchain,
  setSlot,
 )
import Convex.CoinSelection (BalanceTxError)
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)

-- import Convex.TestingInterface (Options, mockchainSucceedsWithOptions, mockchainFailsWithOptions)
import Convex.Utils (failOnError, inBabbage)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Vesting.Utils (VestingState (..), lockVesting, mkScriptHash, mkVestingParams, slotToPosixTime, submitAndGetScriptTxIn, withdrawStep)

-------------------------------------------------------------------------------
-- Unit tests for the Vesting script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ testCase
        "secure some funds with the vesting script"
        (mockchainSucceeds $ failOnError (lockVestingTest @C.ConwayEra 10))
    , testCase
        "secure funds twice with the vesting script"
        (mockchainSucceeds $ failOnError (lockTwiceVestingTest @C.ConwayEra 10))
    , testCase
        "retrieve some funds"
        (mockchainSucceeds $ failOnError (retrieveFundsTest @C.ConwayEra 10 10 20 10 10_000_000))
    , testCase
        "cannot retrieve more than allowed"
        (mockchainFails (failOnError (retrieveFundsTest @C.ConwayEra 10 10 20 15 30_000_000)) (\_ -> pure ()))
    , testCase
        "can retrieve everything at the end"
        (mockchainSucceeds $ failOnError (retrieveFundsTest @C.ConwayEra 10 15 30 20 58_775_000))
    , testCase
        "can retrieve in steps according to the vesting schedule"
        (mockchainSucceeds $ failOnError (retrieveFundsInSteps @C.ConwayEra 10 15))
    , testCase
        "can lock twice and retrieve part of the funds (up to 80 ADA) after first deadline"
        (mockchainSucceeds $ failOnError (lockTwiceAndRetrieveFundsTest @C.ConwayEra 15 0 2000 15 80_000_000))
    , testCase
        "can lock twice and retrieve everything (minus fees) at the end"
        (mockchainSucceeds $ failOnError (lockTwiceAndRetrieveFundsTest @C.ConwayEra 15 0 2000 20 119_103_000))
    , testCase
        "cannot remain less than 40 ADA after first deadline when locking twice"
        (mockchainFails (failOnError (lockTwiceAndRetrieveFundsTest @C.ConwayEra 15 0 2000 15 81_000_000)) (\_ -> pure ()))
    , testCase
        "cannot retrieve more than allowed after second deadline when locking twice"
        (mockchainFails (failOnError (lockTwiceAndRetrieveFundsTest @C.ConwayEra 15 0 2000 20 121_000_000)) (\_ -> pure ()))
    ]

-------------------------------------------------------------------------------
-- Unit Testing Functions
-------------------------------------------------------------------------------

-- | Test: Lock 60 ADA in vesting script.
lockVestingTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => C.SlotNo
  -- ^ Deadline
  -> m ()
lockVestingTest dl = inBabbage @era $ do
  deadline <- slotToPosixTime dl
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 10_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000

-- | Test: Lock 60 ADA twice.
lockTwiceVestingTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => C.SlotNo -- deadline
  -> m ()
lockTwiceVestingTest dl = inBabbage @era $ do
  deadline <- slotToPosixTime dl
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 10_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000
  ------------------------------------------------------------------
  -- Tx2: lock another 40 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 40_000_000

-- | Test: Lock 60 ADA and retrieve some.
retrieveFundsTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo
  -- ^ Deadline
  -> C.SlotNo
  -- ^ Lower validity
  -> C.SlotNo
  -- ^ Upper validity
  -> C.SlotNo
  -- ^ Advance chain to slot
  -> C.Lovelace
  -- ^ Value to withdraw
  -> m ()
retrieveFundsTest dl lowerSlot upperSlot startTime value = inBabbage @era $ do
  deadline <- slotToPosixTime dl
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 5_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000

  let vs0 =
        VestingState
          { vsInputs = [txIn]
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Start the chain at a given slot
  ------------------------------------------------------------------
  setSlot startTime
  ------------------------------------------------------------------
  -- Tx2: withdraw some ADA
  ------------------------------------------------------------------
  void $ withdrawStep MockWallet.w1 lowerSlot upperSlot ownerPKH params vs0 value

-- | Test: Lock once and retrieve in two steps.
retrieveFundsInSteps
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo -- deadline first tranche
  -> C.SlotNo -- deadline second tranche
  -> m ()
retrieveFundsInSteps dl1 dl2 = inBabbage @era $ do
  deadline1 <- slotToPosixTime dl1
  deadline2 <- slotToPosixTime dl2
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline1 20_000_000 deadline2 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000

  let vs0 =
        VestingState
          { vsInputs = [txIn]
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Advance time to the beggining of the contract validity
  ------------------------------------------------------------------
  setSlot dl1
  ------------------------------------------------------------------
  -- Tx2: withdraw only 20 ADA
  ------------------------------------------------------------------
  vs1 <- withdrawStep MockWallet.w1 dl1 (dl1 + 100) ownerPKH params vs0 20_000_000
  ------------------------------------------------------------------
  -- Advance time to after the first tranche deadline
  ------------------------------------------------------------------
  setSlot dl2
  ------------------------------------------------------------------
  -- Tx3: withdraw remaining 40 ADA - fee
  ------------------------------------------------------------------
  void $ withdrawStep MockWallet.w1 dl2 (dl2 + 100) ownerPKH params vs1 38_775_000

-- | Test: Lock twice and retrieve.
lockTwiceAndRetrieveFundsTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo
  -- ^ Deadline
  -> C.SlotNo
  -- ^ Lower validity
  -> C.SlotNo
  -- ^ Upper validity
  -> C.SlotNo
  -- ^ Advance chain to slot
  -> C.Lovelace
  -- ^ Value to withdraw
  -> m ()
lockTwiceAndRetrieveFundsTest dl _ upperSlot startTime value = inBabbage @era $ do
  deadline <- slotToPosixTime dl
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 5_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn1 <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000
  ------------------------------------------------------------------
  -- Tx2: lock another 40 ADA in the vesting script
  ------------------------------------------------------------------
  txIn2 <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash params) $
      lockVesting (mkScriptHash params) 60_000_000
  ------------------------------------------------------------------
  -- Update state considering both locked UTXOs
  ------------------------------------------------------------------
  let vs0 =
        VestingState
          { vsInputs = [txIn1, txIn2]
          , vsLocked = 120_000_000
          }
  ------------------------------------------------------------------
  -- Advance time to the beggining of the contract validity
  ------------------------------------------------------------------
  setSlot startTime
  ------------------------------------------------------------------
  -- Tx3: withdraw some ADA
  ------------------------------------------------------------------
  void $ withdrawStep MockWallet.w1 startTime upperSlot ownerPKH params vs0 value
