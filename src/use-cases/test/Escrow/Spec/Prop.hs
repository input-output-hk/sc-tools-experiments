{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Escrow.Spec.Prop (
  propBasedTests,
) where

import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Control.Monad (void, when)
import Control.Monad.Except (MonadError, runExceptT)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (utxoSet)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (TestingInterface (..), propRunActions)
import Convex.ThreatModel.DoubleSatisfaction (doubleSatisfaction)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.MutualExclusion (mutualExclusionAttack)
import Convex.ThreatModel.SignatoryRemoval (signatoryRemoval)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.ThreatModel.TokenForgery (simpleAlwaysSucceedsMintingPolicyV2, simpleTestAssetName, tokenForgeryAttack)
import Convex.ThreatModel.ValueUnderpayment (valueUnderpaymentAttack)
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Utxos (toApiUtxo)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Escrow.Scripts (escrowValidatorScript)
import Escrow.Validator (Action (..), EscrowParams (..), EscrowTarget (..))
import GHC.Generics (Generic)
import PlutusLedgerApi.V1 (lovelaceValue)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck qualified as QC

-------------------------------------------------------------------------------
-- Property-based tests for the Escrow contract
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ propRunActions @EscrowModel "Property-based test escrow contract"
    ]

-------------------------------------------------------------------------------
-- Escrow Testing Interface
-------------------------------------------------------------------------------

{- | Model of the Escrow contract state for property-based testing.

  Configuration:
  - Contributor: MockWallet.w1
  - Target recipients: MockWallet.w2 (5 ADA) and MockWallet.w3 (5 ADA)
  - Deadline: slot 50
  - Start time: slot 0
-}
data EscrowModel = EscrowModel
  { _contributor :: Wallet
  -- ^ The wallet that locked funds into the escrow
  , _curSlot :: C.SlotNo
  -- ^ The current slot
  , _endSlot :: C.SlotNo
  -- ^ The deadline slot - Redeem must happen before, Refund after
  , _escrowInitialized :: Bool
  -- ^ Whether funds have been locked at the script
  , _escrowSettled :: Bool
  -- ^ Whether the escrow has been settled (Redeem or Refund executed)
  , _scriptHash :: Maybe C.ScriptHash
  -- ^ The validator script hash (set after initialization)
  , _escrowTxIn :: Maybe C.TxIn
  -- ^ The current locked UTxO reference
  }
  deriving (Show, Eq, Generic)

instance TestingInterface EscrowModel where
  data Action EscrowModel
    = LockFunds
    | -- Contributor locks funds into the escrow script
      RedeemFunds
    | -- Spend the escrow UTxO before the deadline, paying all targets
      RefundFunds
    | -- Contributor reclaims funds after the deadline
      WaitSlots C.SlotNo
    -- Advance blockchain time
    deriving (Show, Eq)

  -- Initial state for the escrow scenario.
  --
  --   Configuration:
  --   - Contributor: MockWallet.w1
  --   - Deadline: slot 50
  --   - Start time: slot 0
  --   - Funds not yet locked
  initialize =
    pure
      EscrowModel
        { _contributor = MockWallet.w1
        , _curSlot = 0
        , _endSlot = 50
        , _escrowInitialized = False
        , _escrowSettled = False
        , _scriptHash = Nothing
        , _escrowTxIn = Nothing
        }

  -- Generate random actions weighted by likelihood and current state.
  arbitraryAction em =
    QC.frequency
      [ (lockWeight, genLock)
      , (redeemWeight, genRedeem)
      , (refundWeight, genRefund)
      , (waitWeight, genWait)
      ]
   where
    lockWeight
      | _escrowInitialized em = 0
      | otherwise = 1

    redeemWeight
      | not (_escrowInitialized em) || _escrowSettled em = 1
      | _curSlot em < _endSlot em = 2
      | otherwise = 1 -- too late, still generate occasionally
    refundWeight
      | not (_escrowInitialized em) || _escrowSettled em = 1
      | _curSlot em >= _endSlot em = 2
      | otherwise = 1 -- too early, still generate occasionally
    waitWeight = 1

    genLock = pure LockFunds
    genRedeem = pure RedeemFunds
    genRefund = pure RefundFunds
    genWait = WaitSlots . C.SlotNo <$> Gen.chooseWord64 (1, 20)

  -- Preconditions determine which actions are valid in the current state.
  precondition em LockFunds =
    -- Can only lock once
    not (_escrowInitialized em)
  precondition em RedeemFunds =
    -- Escrow must be initialized and not yet settled
    _escrowInitialized em
      && not (_escrowSettled em)
      -- Redeem is only valid before the deadline
      && _curSlot em < _endSlot em
  precondition em RefundFunds =
    -- Escrow must be initialized and not yet settled
    _escrowInitialized em
      && not (_escrowSettled em)
      -- Refund is only valid after the deadline
      && _curSlot em >= _endSlot em
  -- Time can always advance
  precondition _ (WaitSlots _) = True

  -- nextState updates the model based on actions.
  nextState em LockFunds =
    em
      { _escrowInitialized = True
      , _curSlot = _curSlot em + 1
      }
  nextState em RedeemFunds =
    em
      { _escrowSettled = True
      , _curSlot = _curSlot em + 1
      }
  nextState em RefundFunds =
    em
      { _escrowSettled = True
      , _curSlot = _curSlot em + 1
      }
  nextState em (WaitSlots slots) =
    em
      { _curSlot = _curSlot em + slots
      }

  -- perform executes actions on the actual mockchain.
  perform em LockFunds =
    runExceptT (lockFundsPBT (paramsFromModel em) (_contributor em))
      >>= \case
        Left err -> fail $ "LockFunds failed: " <> show err
        Right _ -> pure ()
  perform em RedeemFunds =
    if not (_escrowInitialized em)
      then fail "Escrow not initialized"
      else
        runExceptT (redeemFundsPBT (paramsFromModel em) (_curSlot em) (_contributor em))
          >>= \case
            Left err -> fail $ "RedeemFunds failed: " <> show err
            Right _ -> pure ()
  perform em RefundFunds =
    if not (_escrowInitialized em)
      then fail "Escrow not initialized"
      else
        runExceptT (refundFundsPBT (paramsFromModel em) (_curSlot em) (_contributor em))
          >>= \case
            Left err -> fail $ "RefundFunds failed: " <> show err
            Right _ -> pure ()
  perform _em (WaitSlots _slots) =
    pure ()

  validate _em = pure True

  threatModels =
    [ doubleSatisfaction
    , largeValueAttackWith 10
    , mutualExclusionAttack
    , signatoryRemoval
    , tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName
    , valueUnderpaymentAttack
    ]
  expectedVulnerabilities = [timeBoundManipulation]

  monitoring _ _ = error "monitoring not implemented"

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

{- | Available contributor wallets for property-based testing.
contributors :: [Wallet]
contributors = [MockWallet.w1, MockWallet.w2, MockWallet.w3]
-}

{- | Fixed PKH targets used across all PBT scenarios.
  w4 receives 5 ADA and w5 receives 5 ADA.
  These are baked into params so all PBT actions share the same script.
-}
pbtTargets :: [EscrowTarget]
pbtTargets =
  [ PaymentPubKeyTarget
      (transPubKeyHash $ verificationKeyHash MockWallet.w4)
      (lovelaceValue 5_000_000)
  , PaymentPubKeyTarget
      (transPubKeyHash $ verificationKeyHash MockWallet.w5)
      (lovelaceValue 5_000_000)
  ]

-- | Total lovelace required to satisfy all targets.
pbtLockedValue :: C.Value
pbtLockedValue = C.lovelaceToValue 10_000_000

{- | Construct EscrowParams from the current model state.
  The deadline is derived from the model's end slot via era history.
-}
paramsFromModel :: EscrowModel -> EscrowParams
paramsFromModel em =
  let endTime =
        case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_endSlot em) of
          Left err -> error $ "paramsFromModel: cannot convert slot to posix time: " ++ show err
          Right t -> utcTimeToPosixTime t
   in EscrowParams
        { epDeadline = endTime
        , epTargets = pbtTargets
        }

-------------------------------------------------------------------------------
-- Property-Based Testing Functions
-------------------------------------------------------------------------------

{- | Lock the required funds at the escrow script.
  The contributor's PKH is stored as the inline datum.
-}
lockFundsPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => EscrowParams
  -> Wallet
  -- ^ Contributor wallet (datum and signing key)
  -> m ()
lockFundsPBT params contributor = do
  let contributorPkh = transPubKeyHash $ verificationKeyHash contributor
  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            contributorPkh
            C.NoStakeAddress
            pbtLockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  void $ tryBalanceAndSubmit mempty contributor lockTx TrailingChange []

{- | Redeem the escrow: spend the script UTxO before the deadline,
  producing one output per target.
-}
redeemFundsPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => EscrowParams
  -> C.SlotNo
  -- ^ Current slot (must be < deadline slot)
  -> Wallet
  -- ^ Wallet submitting the redeem tx
  -> m ()
redeemFundsPBT params curSlot submitter = do
  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript

  -- Query the escrow UTxO from the mockchain
  escrowUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null escrowUtxos) $ fail "No escrow UTxO found on chain"
  let (txIn, _) = head escrowUtxos

  setSlot curSlot

  let redeemTx =
        execBuildTx $ do
          -- Validity range fully within `to deadline`: [curSlot, curSlot + 1)
          BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Redeem
          -- Satisfy each PKH target with the exact required value
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId MockWallet.w4)
            (C.lovelaceToValue 5_000_000)
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId MockWallet.w5)
            (C.lovelaceToValue 5_000_000)

  void $ tryBalanceAndSubmit mempty submitter redeemTx TrailingChange []

{- | Refund the escrow: contributor reclaims funds after the deadline.
  The contributor must sign and the validity range must start after the deadline.
-}
refundFundsPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => EscrowParams
  -> C.SlotNo
  -- ^ Current slot (must be >= deadline slot)
  -> Wallet
  -- ^ Contributor wallet (must match the inline datum at the script UTxO)
  -> m ()
refundFundsPBT params curSlot contributor = do
  let escrowScript = C.PlutusScript C.plutusScriptVersion (escrowValidatorScript params)
      scriptHash = C.hashScript escrowScript
      contributorPkh = verificationKeyHash contributor

  -- Query the escrow UTxO from the mockchain
  escrowUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null escrowUtxos) $ fail "No escrow UTxO found on chain"
  let (txIn, _) = head escrowUtxos

  setSlot curSlot

  let refundTx =
        execBuildTx $ do
          -- Validity range starts after the deadline: (deadline - 1) `before` validRange
          BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
          BuildTx.addRequiredSignature contributorPkh
          BuildTx.spendPlutusInlineDatum txIn (escrowValidatorScript params) Refund

  void $ tryBalanceAndSubmit mempty contributor refundTx TrailingChange []

-- | Fetches the UTxOs at a given script address identified by its script hash.
utxosAt
  :: forall era m
   . (MonadMockchain era m, MonadFail m, C.IsBabbageBasedEra era)
  => C.ScriptHash -> m [(C.TxIn, C.TxOut C.CtxUTxO era)]
utxosAt scriptHash = do
  utxos <- utxoSet
  let scriptUtxos =
        [ (txIn, txOut)
        | (txIn, txOut@(C.TxOut addr _ _ _)) <- C.UTxO.toList (toApiUtxo utxos)
        , isScriptAddress addr
        ]
  pure scriptUtxos
 where
  isScriptAddress (C.AddressInEra _ (C.ShelleyAddress _ (ScriptHashObj h) _)) =
    h == C.toShelleyScriptHash scriptHash
  isScriptAddress _ = False
