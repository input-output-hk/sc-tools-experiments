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

  The 'params' field caches the 'VestingParams' so that 'paramsFromModel'
  (which calls 'slotToUtcTime' twice and builds Plutus values) is only
  computed once per test sequence when 'initialize' runs, not on every
  'perform' call.
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
  -- ^ The current slot in the model (kept in sync with the chain via setSlot)
  , _owner :: Wallet
  -- ^ The beneficiary authorised to withdraw
  , _params :: VestingParams
  -- ^ Cached contract parameters (computed once in 'initialize')
  , _scriptHash :: C.ScriptHash
  -- ^ Cached script hash (computed once in 'initialize')
  }
  deriving (Show, Eq, Generic)

-- Fixed contract parameters used across the whole test run.
fixedOwner :: Wallet
fixedOwner = MockWallet.w1

fixedParams :: VestingParams
fixedParams = buildParams fixedOwner 10 20 20_000_000 40_000_000

fixedScriptHash :: C.ScriptHash
fixedScriptHash =
  let validator = C.PlutusScript C.plutusScriptVersion (vestingValidatorScript fixedParams)
   in C.hashScript validator

instance TestingInterface VestingModel where
  data Action VestingModel
    = Vest Wallet
    | -- \^ Lock funds (both tranches) into the vesting contract
      Retrieve C.Lovelace
    | -- \^ Owner attempts to withdraw the specified amount
      WaitSlots C.SlotNo
    -- \^ Advance blockchain time
    deriving (Show, Eq)

  initialize =
    pure
      VestingModel
        { _vestedAmount = mempty
        , _vested = []
        , _t1Slot = 10
        , _t2Slot = 20
        , _t1Amount = 20_000_000
        , _t2Amount = 40_000_000
        , _curSlot = 0
        , _owner = fixedOwner
        , _params = fixedParams
        , _scriptHash = fixedScriptHash
        }

  arbitraryAction vm =
    QC.frequency $
      [(10, genVest) | nothingLocked]
        ++ [(6, genWait)]
        ++ [(8, genValidRetrieve) | canWithdraw vm]
        ++ [(1, genInvalidRetrieve) | somethingLocked]
   where
    nothingLocked = _vestedAmount vm == 0
    somethingLocked = _vestedAmount vm > 0

    genVest = Vest <$> QC.elements wallets

    -- Bias slot advances toward the two tranche unlock points.
    -- List-comprehension guards ensure every (lo, hi) satisfies lo <= hi.
    genWait =
      WaitSlots . C.SlotNo <$> do
        let cur = C.unSlotNo (_curSlot vm)
            t1 = C.unSlotNo (_t1Slot vm)
            t2 = C.unSlotNo (_t2Slot vm)
        QC.frequency $
          [(3, Gen.chooseWord64 (1, 3))]
            ++ [(4, Gen.chooseWord64 (t1 - cur, t1 - cur + 1)) | cur < t1]
            ++ [(4, Gen.chooseWord64 (t2 - cur, t2 - cur + 1)) | cur < t2]
            ++ [(1, Gen.chooseWord64 (4, 12))]

    -- Generate a withdrawal amount that provably satisfies all preconditions.
    -- 'canWithdraw' guarantees maxAda >= 1 before this branch is offered.
    genValidRetrieve = do
      let locked = _vestedAmount vm
          available = availableTrancheAmount vm
          cur = _curSlot vm
          futureObl =
            (if cur < _t1Slot vm then _t1Amount vm else 0)
              + (if cur < _t2Slot vm then _t2Amount vm else 0)
          maxLove = min available (locked - futureObl - minUtxoThreshold)
          maxAda = C.unCoin maxLove `div` 1_000_000
      amt <- Gen.chooseInteger (1, maxAda)
      pure $ Retrieve (C.Coin (amt * 1_000_000))

    -- Generate an amount that always exceeds total locked → always rejected
    -- by the precondition without touching the chain.
    genInvalidRetrieve = do
      let locked = C.unCoin (_vestedAmount vm)
          minBadAda = locked `div` 1_000_000 + 1
      amt <- Gen.chooseInteger (minBadAda, minBadAda + 5)
      pure $ Retrieve (C.Coin (amt * 1_000_000))

  precondition vm action =
    case action of
      Vest _w -> True
      WaitSlots _ -> True
      Retrieve amt ->
        _vestedAmount vm > 0
          && amt >= 1_000_000
          && amt <= _vestedAmount vm
          && enoughValueLeft vm amt
          && validChangeOutput vm amt

  nextState vm action = case action of
    Vest w ->
      vm
        { _vestedAmount = _vestedAmount vm + (_t1Amount vm + _t2Amount vm)
        , _vested = w : _vested vm
        }
    Retrieve amt ->
      vm
        { _vestedAmount = _vestedAmount vm - amt
        }
    WaitSlots slots ->
      vm{_curSlot = _curSlot vm + slots}

  -- 'perform' uses the cached '_params' and '_scriptHash' from the model,
  -- avoiding repeated 'slotToUtcTime' / script compilation on every action.
  perform vm (Vest w) = do
    runExceptT (fundVestingPBT w (_params vm) (_scriptHash vm))
      >>= \case
        Left err -> fail $ "Vest failed: " <> show err
        Right _ -> pure ()
  perform vm (Retrieve amt) = do
    runExceptT
      ( withdrawPBT
          (_params vm)
          (_scriptHash vm)
          (_curSlot vm)
          (_owner vm)
          amt
          (_vestedAmount vm)
      )
      >>= \case
        Left err -> fail $ "Retrieve failed: " <> show err
        Right _ -> pure ()
  perform vm (WaitSlots slots) =
    -- Advance the chain clock so that subsequent Retrieve actions use the
    -- correct validity range.
    setSlot (_curSlot vm + slots)

  validate _vm = pure True

  threatModels =
    [ largeValueAttackWith 10
    , mutualExclusionAttack
    , signatoryRemoval
    , tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName
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

wallets :: [Wallet]
wallets = [MockWallet.w1, MockWallet.w2, MockWallet.w3]

minUtxoThreshold :: C.Lovelace
minUtxoThreshold = 896_500

{- | Build VestingParams from raw slot/amount values.
Called only once (at top-level) to populate the cache in 'initialize'.
-}
buildParams
  :: Wallet
  -> C.SlotNo
  -- ^ tranche-1 slot
  -> C.SlotNo
  -- ^ tranche-2 slot
  -> C.Lovelace
  -> C.Lovelace
  -> VestingParams
buildParams owner t1Slot t2Slot t1Amt t2Amt =
  let toTime s = case slotToUtcTime Defaults.eraHistory Defaults.systemStart s of
        Left err -> error $ "buildParams: slot->utc: " ++ show err
        Right t -> utcTimeToPosixTime t
   in VestingParams
        { vpOwner = transPubKeyHash $ verificationKeyHash owner
        , vpTranche1 =
            Vesting
              { vDate = toTime t1Slot
              , vAmount = lovelaceValue (fromIntegral $ C.unCoin t1Amt)
              }
        , vpTranche2 =
            Vesting
              { vDate = toTime t2Slot
              , vAmount = lovelaceValue (fromIntegral $ C.unCoin t2Amt)
              }
        }

canWithdraw :: VestingModel -> Bool
canWithdraw vm =
  let locked = _vestedAmount vm
      available = availableTrancheAmount vm
      cur = _curSlot vm
      futureObl =
        (if cur < _t1Slot vm then _t1Amount vm else 0)
          + (if cur < _t2Slot vm then _t2Amount vm else 0)
      maxLove = min available (locked - futureObl - minUtxoThreshold)
   in locked > 0
        && available > 0
        && maxLove >= 1_000_000

availableTrancheAmount :: VestingModel -> C.Lovelace
availableTrancheAmount vm =
  let cur = _curSlot vm
      t1 = if cur >= _t1Slot vm then _t1Amount vm else 0
      t2 = if cur >= _t2Slot vm then _t2Amount vm else 0
   in t1 + t2

enoughValueLeft :: VestingModel -> C.Lovelace -> Bool
enoughValueLeft vm amt =
  let cur = _curSlot vm
      t1r = if cur >= _t1Slot vm then 0 else _t1Amount vm
      t2r = if cur >= _t2Slot vm then 0 else _t2Amount vm
   in (_vestedAmount vm - amt) >= (t1r + t2r)

validChangeOutput :: VestingModel -> C.Lovelace -> Bool
validChangeOutput vm withdrawAmount =
  (_vestedAmount vm - withdrawAmount) >= minUtxoThreshold

-------------------------------------------------------------------------------
-- Mockchain transactions
-------------------------------------------------------------------------------

fundVestingPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => Wallet
  -> VestingParams
  -> C.ScriptHash
  -> m ()
fundVestingPBT w params scriptHash = do
  let t1value = vAmount (vpTranche1 params)
      t2value = vAmount (vpTranche2 params)
      total = getLovelace (lovelaceValueOf t1value + lovelaceValueOf t2value)
      totalLovelace = C.lovelaceToValue $ C.Coin total
      lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            ()
            C.NoStakeAddress
            totalLovelace
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters
  void $ tryBalanceAndSubmit mempty w lockTx TrailingChange []

withdrawPBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => VestingParams
  -> C.ScriptHash
  -> C.SlotNo
  -> Wallet
  -> C.Lovelace
  -> C.Lovelace
  -> m ()
withdrawPBT params scriptHash curSlot ownerWallet amt lockedAmt = do
  vestingUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null vestingUtxos) $ fail "No vesting UTxO found on chain"
  let (txIn, _) = head vestingUtxos
  -- The chain slot was already advanced by 'perform (WaitSlots _)' via
  -- setSlot, so we only need to set it here as a safety re-affirmation.
  setSlot curSlot
  let ownerPkh = verificationKeyHash ownerWallet
      withdrawTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots curSlot (curSlot + 10)
          BuildTx.addRequiredSignature ownerPkh
          BuildTx.spendPlutusInlineDatum txIn (vestingValidatorScript params) ()
          BuildTx.payToPublicKey Defaults.networkId ownerPkh (C.lovelaceToValue amt)
          let remaining = lockedAmt - amt
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            ()
            C.NoStakeAddress
            (C.lovelaceToValue remaining)
  void $ tryBalanceAndSubmit mempty ownerWallet withdrawTx TrailingChange []
