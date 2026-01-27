{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Model.VestingModel (
  VestingModel,
) where

import Cardano.Api qualified as C
import Contracts.Vesting qualified as Vesting
import Control.Monad.Except (runExceptT)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (TestingInterface (..))
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import GHC.Generics (Generic)
import PlutusLedgerApi.V1 (lovelaceValue)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty.QuickCheck qualified as QC
import Utils.VestingUtils qualified as Utils

-------------------------------------------------------------------------------
-- Vesting Testing Interface
-------------------------------------------------------------------------------
data VestingModel = VestingModel
  { _vestedAmount :: C.Lovelace
  -- ^ How much value is in the contract
  , _vested :: [Wallet]
  -- ^ What wallets have already vested money
  , _t1Slot :: C.SlotNo
  -- ^ The time for the first tranche
  , _t2Slot :: C.SlotNo
  -- ^ The time for the second tranche
  , _t1Amount :: C.Lovelace
  -- ^ The size of the first tranche
  , _t2Amount :: C.Lovelace
  -- ^ The size of the second tranche
  , _curSlot :: C.SlotNo
  -- ^ The current slot
  , _owner :: Wallet
  -- ^ The beneficiary of this contract
  }
  deriving (Show, Eq, Generic)

instance TestingInterface VestingModel where
  data Action VestingModel
    = Vest Wallet C.Lovelace
    | -- \^ Lock funds in a vesting contract
      Retrieve C.Lovelace
    | -- \^ Owner attempts to withdraw specified amount
      WaitSlots C.SlotNo
    -- \^ Advance blockchain time
    deriving (Show, Eq)

  -- \| Initial state vesting scenario.
  --
  --    Configuration:
  --    - Two tranches: 20 ADA @ slot 10, 40 ADA @ slot 20
  --    - Total: 60 ADA per vesting contract
  --    - Owner: MockWallet.w1 (the beneficiary)
  --    - Start time: slot 0
  --
  initialState =
    VestingModel
      { _vestedAmount = mempty
      , _vested = []
      , _t1Slot = 10
      , _t2Slot = 20
      , _t1Amount = 20_000_000
      , _t2Amount = 40_000_000
      , _curSlot = 0
      , _owner = MockWallet.w1
      }

  -- \| Generate random actions weighted by likelihood and current state.
  arbitraryAction vm =
    QC.frequency
      [ (vestWeight, genVest)
      , (withdrawWeight, genWithdraw)
      , (waitWeight, genWait)
      ]
   where
    -- Weights adjust based on state
    vestWeight = if _vestedAmount vm == 0 then 5 else 2
    withdrawWeight = if _vestedAmount vm > 0 then 5 else 1
    waitWeight = 3

    genVest = do
      wallet <- QC.elements wallets
      -- Vest the full amount (both tranches)
      pure $ Vest wallet (_t1Amount vm + _t2Amount vm)

    genWithdraw = do
      -- Generate withdrawal amounts from 1 ADA to total locked amount
      let maxWithdraw = max 1_000_000 (C.unCoin $ _vestedAmount vm)
      amt <- Gen.chooseInteger (1_000_000, maxWithdraw)
      pure $ Retrieve (C.Coin amt)

    genWait = do
      -- Advance 1-15 slots
      slots <- C.SlotNo <$> Gen.chooseWord64 (1, 15)
      pure $ WaitSlots slots

  -- \| Preconditions determine which actions are valid in the current state.
  -- Anyone can vest at any time, except the owner
  precondition vm (Vest w _) =
    w /= _owner vm -- Don't let the owner vest (they're the beneficiary, not the grantor)
    -- Withdrawals have complex preconditions based on time and amounts
  precondition vm (Retrieve amt) =
    _vestedAmount vm > 0
      && amt >= 1_000_000 -- Must have funds locked
      && amt <= _vestedAmount vm -- Must withdraw at least 1 ADA
      && enoughValueLeft vm amt -- Must not withdraw more than what's locked
      && _curSlot vm >= _t1Slot vm -- Must leave enough to satisfy remaining tranches
      && validChangeOutput vm amt -- Only test withdrawals after first tranche is available
      -- added to avoid changes with less than 1 ADA
      -- Time can always advance
  precondition _ (WaitSlots _) = True

  -- \| nextState updates the model based on actions.
  -- Vest the sum of the two tranches
  nextState vm (Vest w amt) =
    vm
      { _vestedAmount = _vestedAmount vm + amt
      , _vested = w : _vested vm
      , _curSlot = _curSlot vm + 1 -- advancing time in 1 slot
      }
  -- Retrieve `v` value as long as that leaves enough value to satisfy
  -- the tranche requirements
  nextState vm (Retrieve amt) =
    vm
      { _vestedAmount = _vestedAmount vm - amt
      , _curSlot = _curSlot vm + 1 -- advancing time in 1 slot
      }
  nextState vm (WaitSlots slots) =
    vm
      { _curSlot = _curSlot vm + slots
      }

  -- \| perform executes actions on the actual blockchain.
  perform vm (Vest w amt) =
    do
      C.liftIO $ putStrLn $ ">>> Vesting " ++ show amt ++ " lovelace from " ++ show w
      runExceptT $
        Utils.lockVestingPBT @C.ConwayEra (_t1Slot vm) w amt
      >>= \case
        Left err -> fail $ "Vest failed: " <> show err
        Right _txId -> pure ()
  perform vm (Retrieve amt) =
    do
      C.liftIO $ putStrLn $ ">>> Withdrawing " ++ show amt ++ " lovelace at slot " ++ show (_curSlot vm)
      let vestingParams = mkVestingParams vm
      runExceptT $
        Utils.retrieveFundsPBT @C.ConwayEra
          vestingParams
          (_curSlot vm) -- lowerSlot: current time
          (_curSlot vm + 100) -- upperSlot: give some validity range
          (_curSlot vm) -- set chain to current slot
          amt
      >>= \case
        Left err -> fail $ "Withdraw failed: " <> show err
        Right _txId -> pure ()
  perform vm (WaitSlots slots) =
    do
      C.liftIO $ putStrLn $ ">>> Waiting " ++ show slots ++ " slots (now at " ++ show (_curSlot vm + slots) ++ ")"
      pure () -- do nothing

  validate _vm = pure True

  monitoring _ _ = error "monitoring not implemented"

-------------------------------------------------------------------------------
-- Helper functions for the VestingModel
-------------------------------------------------------------------------------

wallets :: [Wallet]
wallets = [MockWallet.w1, MockWallet.w2, MockWallet.w3]

-- | Create VestingParams matching the model state.
mkVestingParams :: VestingModel -> Vesting.VestingParams
mkVestingParams vm =
  let dt1 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_t1Slot vm) of
        Left err -> error $ "mkVestingParams: cannot convert slot to utc time: " ++ show err
        Right t -> t
      dt2 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_t2Slot vm) of
        Left err -> error $ "mkVestingParams: cannot convert slot to utc time: " ++ show err
        Right t -> t
   in Vesting.VestingParams
        { Vesting.vpOwner = transPubKeyHash $ verificationKeyHash (_owner vm)
        , Vesting.vpTranche1 =
            Vesting.Vesting
              { Vesting.vDate = utcTimeToPosixTime dt1
              , Vesting.vAmount = lovelaceValue (fromIntegral $ C.unCoin $ _t1Amount vm)
              }
        , Vesting.vpTranche2 =
            Vesting.Vesting
              { Vesting.vDate = utcTimeToPosixTime dt2
              , Vesting.vAmount = lovelaceValue (fromIntegral $ C.unCoin $ _t2Amount vm)
              }
        }

-- | Check if a withdrawal leaves enough value for remaining tranches.
enoughValueLeft :: VestingModel -> C.Lovelace -> Bool
enoughValueLeft vm amt =
  let currentSlot = _curSlot vm
      -- How much is still locked (not yet released by time)
      tranche1Remaining = if currentSlot >= _t1Slot vm then 0 else _t1Amount vm
      tranche2Remaining = if currentSlot >= _t2Slot vm then 0 else _t2Amount vm
      totalRemaining = tranche1Remaining + tranche2Remaining
      -- How much will be left in contract after withdrawal
      valueAfterWithdraw = _vestedAmount vm - amt
   in valueAfterWithdraw >= totalRemaining

validChangeOutput :: VestingModel -> C.Lovelace -> Bool
validChangeOutput vm withdrawAmount =
  let remaining = _vestedAmount vm - withdrawAmount
      minUtxo = 1_000_000 -- 1 ADA
   in remaining == 0 -- OK: retrieves everything
        || remaining >= minUtxo -- OK: leaves at least 1 ADA
