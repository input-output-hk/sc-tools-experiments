{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeApplications #-}

module Utils.VestingUtils (
  lockVestingTest,
  lockTwiceVestingTest,
  retrieveFundsTest,
  retrieveFundsInSteps,
  lockTwiceAndRetrieveFundsTest,
  vestingScriptTest,
  VestingState (..),
) where

import Control.Monad (forM_, void)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (
  TxBuilder,
  addRequiredSignature,
  addValidityRangeSlots,
  execBuildTx,
 )

import Cardano.Api (SlotNo)
import Cardano.Api qualified as C
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Contracts.Vesting qualified as Vesting
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  MonadBlockchain (..),
  MonadMockchain,
  setSlot,
 )
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.Utils (inBabbage, slotToUtcTime, utcTimeToPosixTime)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import PlutusLedgerApi.V1 (POSIXTime, lovelaceValue)
import Scripts.VestingScript qualified as Script

-------------------------------------------------------------------------------
-- Auxiliary functions and definitions for the tests
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
-- Vesting State
-------------------------------------------------------------------------------

data VestingState = VestingState
  { vsInputs :: [C.TxIn]
  , vsLocked :: C.Lovelace
  }

-------------------------------------------------------------------------------
-- Helper functions to build and submit transactions
-------------------------------------------------------------------------------

-- submitAndGetTxIn
--   :: forall era m
--    . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
--   => Wallet -> Word -> TxBuilder era -> m C.TxIn
-- submitAndGetTxIn w idx builder = do
--   txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty w builder TrailingChange []
--   pure $ C.TxIn txId (C.TxIx idx)

submitAndGetScriptTxIn
  :: forall era m
   . ( MonadMockchain era m
     , MonadError (BalanceTxError era) m
     , MonadFail m
     , C.IsBabbageBasedEra era
     )
  => Wallet
  -> C.ScriptHash
  -> TxBuilder era
  -> m C.TxIn
submitAndGetScriptTxIn wallet scriptHash txBuilder = do
  -- Balance, sign and submit the transaction.
  tx <- tryBalanceAndSubmit mempty wallet txBuilder TrailingChange []
  let
    txBody = C.getTxBody tx
    txId = C.getTxId txBody
    -- Enumerate transaction outputs and assign TxIx values
    outputs =
      zip [C.TxIx 0 ..] $
        C.txOuts (C.getTxBodyContent txBody)
    -- Select outputs whose address is locked by the given script hash
    scriptOutputs =
      [ C.TxIn txId ix
      | (ix, C.TxOut addr _ _ _) <- outputs
      , isScriptAddress addr
      ]
  -- We expect exactly one script output
  case scriptOutputs of
    [txIn] -> pure txIn
    [] -> fail "submitAndGetScriptTxIn: no script output found"
    _ -> fail "submitAndGetScriptTxIn: multiple script outputs found"
 where
  isScriptAddress :: C.AddressInEra era -> Bool
  isScriptAddress (C.AddressInEra _ addr) =
    case addr of
      C.ShelleyAddress _ payment _ ->
        case payment of
          ScriptHashObj h ->
            h == C.toShelleyScriptHash scriptHash
          _ -> False
      _ -> False

lockVesting
  :: forall era
   . (C.IsBabbageBasedEra era)
  => C.ScriptHash -> C.Lovelace -> TxBuilder era
lockVesting scriptHash lovelace =
  execBuildTx $
    BuildTx.payToScriptInlineDatum
      Defaults.networkId
      scriptHash
      ()
      C.NoStakeAddress
      (C.lovelaceToValue lovelace)

withdrawVesting
  :: forall era
   . (C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo -> C.SlotNo -> C.Hash C.PaymentKey -> Vesting.VestingParams -> VestingState -> C.Lovelace -> TxBuilder era
withdrawVesting lower upper pkh vestingParams vtState lovelace =
  execBuildTx $ do
    -- Here is where we set the validity range for the transaction
    -- It needs to be within the vesting schedule, i.e., the lower validity should be after the deadlines
    -- For each transaction, we update the lower validity to be after the previous one, considering the current slot
    addValidityRangeSlots lower upper
    addRequiredSignature pkh
    -- Consume ALL script UTXO
    forM_ (vsInputs vtState) $ \txIn ->
      BuildTx.spendPlutusInlineDatum txIn (Script.vestingValidatorScript vestingParams) ()
    -- Pay to owner's public key
    BuildTx.payToPublicKey Defaults.networkId pkh (C.lovelaceToValue lovelace)
    -- Return remaining to the script
    let remainingLovelace = vsLocked vtState - lovelace
    BuildTx.payToScriptInlineDatum
      Defaults.networkId
      (mkScriptHash vestingParams)
      ()
      C.NoStakeAddress
      (C.lovelaceToValue remainingLovelace)

withdrawStep
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => Wallet
  -> C.SlotNo
  -> C.SlotNo
  -> C.Hash C.PaymentKey
  -> Vesting.VestingParams
  -> VestingState
  -> C.Lovelace
  -> m VestingState
withdrawStep w lower upper pkh vestingParams vtState lovelace = do
  newTxIn <-
    submitAndGetScriptTxIn
      w
      (mkScriptHash vestingParams)
      (withdrawVesting lower upper pkh vestingParams vtState lovelace)

  pure $
    VestingState
      { vsInputs = [newTxIn]
      , vsLocked = vsLocked vtState - lovelace
      }

-------------------------------------------------------------------------------
-- Helper functions
-------------------------------------------------------------------------------
mkVestingParams
  :: C.Hash C.PaymentKey
  -> POSIXTime
  -> Integer
  -> POSIXTime
  -> Integer
  -> Vesting.VestingParams
mkVestingParams pkh dl1 val1 dl2 val2 =
  Vesting.VestingParams
    (transPubKeyHash pkh)
    (Vesting.Vesting dl1 (lovelaceValue (fromIntegral val1)))
    (Vesting.Vesting dl2 (lovelaceValue (fromIntegral val2)))

mkScriptHash :: Vesting.VestingParams -> C.ScriptHash
mkScriptHash vestingParams =
  let validator = C.PlutusScript C.plutusScriptVersion (Script.vestingValidatorScript vestingParams)
   in C.hashScript validator

-------------------------------------------------------------------------------
-- Test functions
-------------------------------------------------------------------------------

lockVestingTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => C.SlotNo -- deadline
  -> m ()
lockVestingTest dl = inBabbage @era $ do
  dlInUtc <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl >>= either fail pure
  let deadline = utcTimeToPosixTime dlInUtc
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 10_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000

lockTwiceVestingTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => C.SlotNo -- deadline
  -> m ()
lockTwiceVestingTest dl = inBabbage @era $ do
  dlInUtc <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl >>= either fail pure
  let deadline = utcTimeToPosixTime dlInUtc
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 10_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000
  ------------------------------------------------------------------
  -- Tx2: lock another 40 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 40_000_000

retrieveFundsTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => SlotNo -- deadline
  -> C.SlotNo -- lower validity
  -> C.SlotNo -- upper validity
  -> C.SlotNo -- advance chain to slot
  -> C.Lovelace -- value to withdraw
  -> m ()
retrieveFundsTest dl lowerSlot upperSlot startTime value = inBabbage @era $ do
  dlInUtc <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl >>= either fail pure
  let deadline = utcTimeToPosixTime dlInUtc
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 5_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000

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
  void $ withdrawStep MockWallet.w1 lowerSlot upperSlot ownerPKH vestingParams vs0 value

retrieveFundsInSteps
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo -- deadline first tranche
  -> C.SlotNo -- deadline second tranche
  -> m ()
retrieveFundsInSteps dl1 dl2 = inBabbage @era $ do
  dlInUtc1 <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl1 >>= either fail pure
  dlInUtc2 <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl2 >>= either fail pure
  let deadline1 = utcTimeToPosixTime dlInUtc1
      deadline2 = utcTimeToPosixTime dlInUtc2
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams = mkVestingParams ownerPKH deadline1 20_000_000 deadline2 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000

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
  vs1 <- withdrawStep MockWallet.w1 dl1 (dl1 + 100) ownerPKH vestingParams vs0 20_000_000
  ------------------------------------------------------------------
  -- Advance time to after the first tranche deadline
  ------------------------------------------------------------------
  setSlot dl2
  ------------------------------------------------------------------
  -- Tx3: withdraw remaining 40 ADA - fee
  ------------------------------------------------------------------
  void $ withdrawStep MockWallet.w1 dl2 (dl2 + 100) ownerPKH vestingParams vs1 38_775_000

lockTwiceAndRetrieveFundsTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo -- deadline
  -> C.SlotNo -- lower validity
  -> C.SlotNo -- upper validity
  -> C.SlotNo -- advance chain to slot
  -> C.Lovelace -- value to withdraw
  -> m ()
lockTwiceAndRetrieveFundsTest dl _ upperSlot startTime value = inBabbage @era $ do
  dlInUtc <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl >>= either fail pure
  let deadline = utcTimeToPosixTime dlInUtc
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 5_000) 40_000_000
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn1 <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000
  ------------------------------------------------------------------
  -- Tx2: lock another 40 ADA in the vesting script
  ------------------------------------------------------------------
  txIn2 <-
    submitAndGetScriptTxIn MockWallet.w1 (mkScriptHash vestingParams) $
      lockVesting (mkScriptHash vestingParams) 60_000_000
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
  void $ withdrawStep MockWallet.w1 startTime upperSlot ownerPKH vestingParams vs0 value

vestingScriptTest
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo -- deadline
  -> C.SlotNo -- lower validity
  -> C.SlotNo -- upper validity
  -> C.SlotNo -- advance chain to slot
  -> C.Lovelace -- value to withdraw
  -> m ()
vestingScriptTest dl lowerSlot upperSlot wSlot value = inBabbage @era $ do
  dlInUtc1 <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure dl >>= either fail pure
  dlInUtc2 <- slotToUtcTime <$> queryEraHistory <*> querySystemStart <*> pure (dl + 5) >>= either fail pure
  let deadline1 = utcTimeToPosixTime dlInUtc1
      deadline2 = utcTimeToPosixTime dlInUtc2
      ownerPKH = verificationKeyHash MockWallet.w1
      vestingParams =
        Vesting.VestingParams
          (transPubKeyHash ownerPKH)
          (Vesting.Vesting deadline1 (lovelaceValue 20_000_000))
          (Vesting.Vesting deadline2 (lovelaceValue 40_000_000))
      validator = C.PlutusScript C.plutusScriptVersion (Script.vestingValidatorScript vestingParams)
      scriptHash = C.hashScript validator
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetScriptTxIn MockWallet.w1 scriptHash $
      lockVesting scriptHash 60_000_000

  let vs0 =
        VestingState
          { vsInputs = [txIn]
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Advance time to the beggining of the contract validity
  ------------------------------------------------------------------
  setSlot wSlot
  ------------------------------------------------------------------
  -- Tx2: withdraw only 20 ADA
  ------------------------------------------------------------------
  void $ withdrawStep MockWallet.w1 lowerSlot upperSlot ownerPKH vestingParams vs0 value

-- vts1 <- withdrawStep MockWallet.w1 1 lowerSlot upperSlot (verificationKeyHash MockWallet.w2) scriptHash datum vts0 20_000_000
------------------------------------------------------------------
-- Advance time to after the first tranche deadline
------------------------------------------------------------------
-- waitNSlots 10
------------------------------------------------------------------
-- Tx3: withdraw remaining 40 ADA - fee
------------------------------------------------------------------
-- void $ withdrawStep Defaults.networkId MockWallet.w1 2 lowerSlot upperSlot ownerPKH scriptHash datum vts1 30_000_000 --38_775_000
-- void $ withdrawStep Defaults.networkId MockWallet.w1 2 lowerSlot upperSlot (verificationKeyHash MockWallet.w2) scriptHash datum vts1 30_000_000 --38_775_000
