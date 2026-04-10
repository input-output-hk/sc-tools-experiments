{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Vesting.Spec.Prop (
  propBasedTests,
) where

import Cardano.Api qualified as C
import Control.Monad (void, when)
import Control.Monad.Except (MonadError, runExceptT)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (RunOptions, TestingInterface (..), propRunActionsWithOptions)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.MutualExclusion (mutualExclusionAttack)
import Convex.ThreatModel.SignatoryRemoval (signatoryRemoval)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.ThreatModel.TokenForgery (simpleAlwaysSucceedsMintingPolicyV2, simpleTestAssetName, tokenForgeryAttack)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.ThreatModel.ValueUnderpayment (valueUnderpaymentAttack)
import Convex.UseCases.Utils (utxosAt)
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import GHC.Generics (Generic)
import PlutusLedgerApi.V1 (Lovelace (getLovelace), lovelaceValue, lovelaceValueOf)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck qualified as QC
import Vesting.Scripts (vestingValidatorScript)
import Vesting.Validator (Vesting (..), VestingParams (..))

-------------------------------------------------------------------------------
-- Property-based tests for the Vesting contract
-------------------------------------------------------------------------------

propBasedTests :: RunOptions -> TestTree
propBasedTests runOpts =
  testGroup
    "property-based tests"
    [ propRunActionsWithOptions @VestingModel "Property-based test vesting script" runOpts
    ]

-------------------------------------------------------------------------------
-- Vesting Testing Interface
-------------------------------------------------------------------------------

{- | Model of the Vesting contract state for property-based testing.

  Configuration:
  - Owner: MockWallet.w1
  - Tranche 1: 20 ADA unlocks at slot 10
  - Tranche 2: 40 ADA unlocks at slot 20
  - Total locked: 60 ADA per vesting contract
-}
data VestingModel = VestingModel
  { _vestedAmount :: C.Lovelace
  -- ^ How much value is currently locked in the contract
  , _vested :: [Wallet]
  -- ^ Wallets that have already funded the contract
  , _t1Slot :: C.SlotNo
  -- ^ Slot at which tranche 1 becomes available
  , _t2Slot :: C.SlotNo
  -- ^ Slot at which tranche 2 becomes available
  , _t1Amount :: C.Lovelace
  -- ^ Lovelace locked in tranche 1
  , _t2Amount :: C.Lovelace
  -- ^ Lovelace locked in tranche 2
  , _curSlot :: C.SlotNo
  -- ^ The current slot
  , _owner :: Wallet
  -- ^ The beneficiary authorised to withdraw
  }
  deriving (Show, Eq, Generic)

instance TestingInterface VestingModel where
  data Action VestingModel
    = Vest Wallet
    | -- \^ Lock funds (both tranches) into the vesting contract
      Retrieve C.Lovelace
    | -- \^ Owner attempts to withdraw the specified amount
      WaitSlots C.SlotNo
    -- \^ Advance blockchain time
    deriving (Show, Eq)

  -- \| Initial model state.
  --
  --   Configuration:
  --   - Two tranches: 20 ADA @ slot 10, 40 ADA @ slot 20
  --   - Total: 60 ADA per vesting contract
  --   - Owner: MockWallet.w1 (the beneficiary)
  --   - Start time: slot 0
  initialize =
    pure
      VestingModel
        { _vestedAmount = mempty
        , _vested = []
        , _t1Slot = 10
        , _t2Slot = 20
        , _t1Amount = 20_000_000 -- 20 ADA
        , _t2Amount = 40_000_000 -- 40 ADA
        , _curSlot = 0
        , _owner = MockWallet.w1
        }

  -- \| Generate random actions weighted by the current model state.
  arbitraryAction vm =
    QC.frequency
      [ (vestWeight, genVest)
      , (withdrawWeight, genWithdraw)
      , (waitWeight, genWait)
      ]
   where
    vestWeight = if _vestedAmount vm == 0 then 5 else 2
    withdrawWeight = if _vestedAmount vm > 0 then 5 else 2
    waitWeight = 3

    genVest = do
      wallet <- QC.elements wallets
      -- Vest the full amount (both tranches combined)
      pure $ Vest wallet

    genWithdraw = do
      -- Generate withdrawal amounts from 1 ADA up to total locked
      let available = availableTrancheAmount vm
      -- This refactoring was done to allow fast testing (using only ADAs, instead of Lovelaces)
      let maxWithdraw = max 1 (C.unCoin available `div` 1_000_000) -- at least 1 ADA, even if nothing is vested yet
      amt <- Gen.chooseInteger (1, maxWithdraw + 10)

      pure $ Retrieve (C.Coin amt)

    genWait = do
      -- Advance 1–15 slots
      slots <- C.SlotNo <$> Gen.chooseWord64 (1, 15)
      pure $ WaitSlots slots

  -- \| Preconditions determine which actions are valid in the current state.
  precondition vm action =
    case action of
      Vest _w -> True
      Retrieve amt ->
        _vestedAmount vm > 0
          && amt >= 1_000_000 -- withdraw at least 1 ADA
          && amt <= _vestedAmount vm -- cannot withdraw more than what is locked
          && enoughValueLeft vm amt -- remaining funds satisfy future tranches
          && validChangeOutput vm amt -- leftover UTxO must meet minUTxO
      WaitSlots _ -> True

  -- \| nextState: pure model transition.
  nextState vm action = case action of
    Vest w ->
      vm
        { _vestedAmount = _vestedAmount vm + (_t1Amount vm + _t2Amount vm)
        , _vested = w : _vested vm
        , _curSlot = _curSlot vm + 1
        }
    Retrieve amt ->
      vm
        { _vestedAmount = _vestedAmount vm - amt
        , _curSlot = _curSlot vm + 1
        }
    WaitSlots slots ->
      vm{_curSlot = _curSlot vm + slots}

  -- \| perform: execute actions against the mockchain.
  perform vm (Vest w) = do
    runExceptT (fundVestingPBT w (paramsFromModel vm))
      >>= \case
        Left err -> fail $ "Vest failed: " <> show err
        Right _ -> pure ()
  perform vm (Retrieve amt) = do
    runExceptT
      ( withdrawPBT
          (paramsFromModel vm)
          (_curSlot vm)
          (_owner vm)
          amt
          (_vestedAmount vm)
      )
      >>= \case
        Left err -> fail $ "Retrieve failed: " <> show err
        Right _ -> pure ()
  perform _vm (WaitSlots _) = pure ()

  validate _vm = pure True

  threatModels =
    [ largeValueAttackWith 10
    , mutualExclusionAttack
    , signatoryRemoval
    , tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName
    , unprotectedScriptOutput
    , unprotectedScriptOutput
    , valueUnderpaymentAttack
    ]

  expectedVulnerabilities =
    [ timeBoundManipulation
    ]

  monitoring _ _ = error "monitoring not implemented"

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------

-- | Available wallets for vesting (funders, not necessarily the owner).
wallets :: [Wallet]
wallets = [MockWallet.w1, MockWallet.w2, MockWallet.w3]

{- | Build 'VestingParams' from the current model state.
  Slot numbers are converted to POSIX times via the era history bundled
  with the mock chain.
-}
paramsFromModel :: VestingModel -> VestingParams
paramsFromModel vm =
  let dt1 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_t1Slot vm) of
        Left err -> error $ "paramsFromModel: cannot convert slot to utc time: " ++ show err
        Right t -> t
      dt2 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_t2Slot vm) of
        Left err -> error $ "paramsFromModel: cannot convert slot to utc time: " ++ show err
        Right t -> t
   in VestingParams
        { vpOwner = transPubKeyHash $ verificationKeyHash (_owner vm)
        , vpTranche1 =
            Vesting
              { vDate = utcTimeToPosixTime dt1
              , vAmount = lovelaceValue (fromIntegral $ C.unCoin $ _t1Amount vm)
              }
        , vpTranche2 =
            Vesting
              { vDate = utcTimeToPosixTime dt2
              , vAmount = lovelaceValue (fromIntegral $ C.unCoin $ _t2Amount vm)
              }
        }

-- | Calculate how much of the vested amount is currently available for withdrawal
availableTrancheAmount :: VestingModel -> C.Lovelace
availableTrancheAmount vm =
  let currentSlot = _curSlot vm
      t1Available = if currentSlot >= _t1Slot vm then _t1Amount vm else 0
      t2Available = if currentSlot >= _t2Slot vm then _t2Amount vm else 0
   in t1Available + t2Available

{- | A withdrawal is only valid if the value left in the contract after it
  satisfies every tranche whose deadline has not yet passed.
-}
enoughValueLeft :: VestingModel -> C.Lovelace -> Bool
enoughValueLeft vm amt =
  let currentSlot = _curSlot vm
      tranche1Remaining = if currentSlot >= _t1Slot vm then 0 else _t1Amount vm
      tranche2Remaining = if currentSlot >= _t2Slot vm then 0 else _t2Amount vm
      totalRemaining = tranche1Remaining + tranche2Remaining
      valueAfterWithdraw = _vestedAmount vm - amt
   in valueAfterWithdraw >= totalRemaining

{- | The change output returned to the script must meet the minimum UTxO
  threshold.  A full withdrawal (remainder == 0) is excluded from testing
  so the contract can be reused across multiple withdrawals.
-}
validChangeOutput :: VestingModel -> C.Lovelace -> Bool
validChangeOutput vm withdrawAmount =
  let remaining = _vestedAmount vm - withdrawAmount
      minUtxo = 896_500
   in remaining >= minUtxo

-------------------------------------------------------------------------------
-- Mockchain transactions
-------------------------------------------------------------------------------

-- | Lock the full vesting amount into the script.
fundVestingPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => Wallet
  -> VestingParams
  -> m ()
fundVestingPBT w params = do
  let validator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
      scriptHash = C.hashScript validator
      t1value = vAmount (vpTranche1 params)
      t2value = vAmount (vpTranche2 params)
      total = getLovelace (lovelaceValueOf t1value + lovelaceValueOf t2value)
      totalLovelace = C.lovelaceToValue $ C.Coin total

      -- The vesting validator uses no datum (BuiltinUnit redeemer)
      lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            () -- datum (unit)
            C.NoStakeAddress
            totalLovelace
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  void $ tryBalanceAndSubmit mempty w lockTx TrailingChange []

{- | Spend the vesting UTxO, sending the withdrawable portion to the owner
  and returning the remainder (if any) back to the script.
-}
withdrawPBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => VestingParams
  -- ^ Contract parameters
  -> C.SlotNo
  -- ^ Current slot (used for validity range)
  -> Wallet
  -- ^ Owner wallet – must sign the transaction
  -> C.Lovelace
  -- ^ Lovelace that must remain locked in the script after withdrawal
  -> C.Lovelace
  -- ^ Total amount currently locked in the script (for calculating change)
  -> m ()
withdrawPBT params curSlot ownerWallet amt lockedAmt = do
  let validator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript params)
      scriptHash = C.hashScript validator

  -- Find the script UTxO on chain
  vestingUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null vestingUtxos) $ fail "No vesting UTxO found on chain"

  let (txIn, _) = head vestingUtxos

  setSlot curSlot

  let ownerPkh = verificationKeyHash ownerWallet

  let withdrawTx =
        execBuildTx $ do
          -- Validity range must start at curSlot so the validator can check
          -- 'from trancheDate `contains` validRange'.
          BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
          -- Owner must sign
          BuildTx.addRequiredSignature ownerPkh
          -- Spend the script UTxO; the vesting validator takes no redeemer
          -- (BuiltinUnit), so we pass unit here.
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          -- Pay withdrawal amount to owner
          BuildTx.payToPublicKey Defaults.networkId ownerPkh (C.lovelaceToValue amt)
          -- Return remaining to the script
          let remaining = lockedAmt - amt
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            ()
            C.NoStakeAddress
            (C.lovelaceToValue remaining)

  void $ tryBalanceAndSubmit mempty ownerWallet withdrawTx TrailingChange []
