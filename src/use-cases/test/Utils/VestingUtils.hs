{-# LANGUAGE TypeApplications #-}

module Utils.VestingUtils (
  lockVestingTest,
  retrieveFundsTest,
  retrieveFundsInSteps,
  vestingScriptTest,
  VestingState (..),
) where

-- import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (
  TxBuilder,
  addRequiredSignature,
  addValidityRangeSlots,
  execBuildTx,
 )

-- import Convex.BuildTx qualified as BuildTx

-- getSlot,

import Cardano.Api (SlotNo)
import Cardano.Api qualified as C
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
import PlutusLedgerApi.V1 (lovelaceValue)
import Scripts.VestingScript qualified as Script

-------------------------------------------------------------------------------
-- Auxiliary functions and definitions for the tests
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
-- Vesting State
-------------------------------------------------------------------------------

data VestingState = VestingState
  { vsInput :: C.TxIn
  , vsLocked :: C.Lovelace
  }

-------------------------------------------------------------------------------
-- Helper functions to build and submit transactions
-------------------------------------------------------------------------------

submitAndGetTxIn
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => Wallet -> Word -> TxBuilder era -> m C.TxIn
submitAndGetTxIn w idx builder = do
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty w builder TrailingChange []
  pure $ C.TxIn txId (C.TxIx idx)

lockVesting
  :: forall era
   . (C.IsBabbageBasedEra era)
  => C.NetworkId -> C.ScriptHash -> Vesting.VestingParams -> C.Lovelace -> TxBuilder era
lockVesting nid scriptHash vestingParams lovelace =
  execBuildTx $
    BuildTx.payToScriptInlineDatum
      nid
      scriptHash
      vestingParams
      C.NoStakeAddress
      (C.lovelaceToValue lovelace)

withdrawVesting
  :: forall era
   . (C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.NetworkId -> C.SlotNo -> C.SlotNo -> C.Hash C.PaymentKey -> C.ScriptHash -> Vesting.VestingParams -> VestingState -> C.Lovelace -> TxBuilder era
withdrawVesting nid lower upper pkh scriptHash vestingParams vtState lovelace =
  execBuildTx $ do
    addValidityRangeSlots lower upper
    addRequiredSignature pkh
    -- Consume UTXO
    BuildTx.spendPlutusInlineDatum (vsInput vtState) Script.vestingValidatorScript ()
    -- Pay to owner's public key
    BuildTx.payToPublicKey nid pkh (C.lovelaceToValue lovelace)
    -- Return remaining to the script
    let remainingLovelace = vsLocked vtState - lovelace
    BuildTx.payToScriptInlineDatum
      nid
      scriptHash
      vestingParams
      C.NoStakeAddress
      (C.lovelaceToValue remainingLovelace)

withdrawStep
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.NetworkId
  -> Wallet
  -> Word -- tx index
  -> C.SlotNo
  -> C.SlotNo
  -> C.Hash C.PaymentKey
  -> C.ScriptHash
  -> Vesting.VestingParams
  -> VestingState
  -> C.Lovelace
  -> m VestingState
withdrawStep nid w idx lower upper pkh scriptHash vestingParams vtState lovelace = do
  txIn <-
    submitAndGetTxIn w idx $
      withdrawVesting nid lower upper pkh scriptHash vestingParams vtState lovelace
  pure $
    VestingState
      { vsInput = txIn
      , vsLocked = vsLocked vtState - lovelace
      }

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
      validator = C.PlutusScript C.plutusScriptVersion Script.vestingValidatorScript
      scriptHash = C.hashScript validator
      ownerPKH = verificationKeyHash MockWallet.w1
      datum =
        Vesting.VestingParams
          (transPubKeyHash ownerPKH)
          (Vesting.Vesting deadline (lovelaceValue 20_000_000))
          (Vesting.Vesting (deadline + 10_000) (lovelaceValue 40_000_000))
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  void $
    submitAndGetTxIn MockWallet.w1 0 $
      lockVesting Defaults.networkId scriptHash datum 60_000_000

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
      validator = C.PlutusScript C.plutusScriptVersion Script.vestingValidatorScript
      scriptHash = C.hashScript validator
      ownerPKH = verificationKeyHash MockWallet.w1
      datum =
        Vesting.VestingParams
          (transPubKeyHash ownerPKH)
          (Vesting.Vesting deadline (lovelaceValue 20_000_000))
          (Vesting.Vesting (deadline + 5_000) (lovelaceValue 40_000_000))
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetTxIn MockWallet.w1 0 $
      lockVesting Defaults.networkId scriptHash datum 60_000_000

  let vs0 =
        VestingState
          { vsInput = txIn
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Start the chain at a given slot
  ------------------------------------------------------------------
  setSlot startTime
  ------------------------------------------------------------------
  -- Tx2: withdraw some ADA
  ------------------------------------------------------------------
  void $ withdrawStep Defaults.networkId MockWallet.w1 1 lowerSlot upperSlot ownerPKH scriptHash datum vs0 value

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
      validator = C.PlutusScript C.plutusScriptVersion Script.vestingValidatorScript
      scriptHash = C.hashScript validator
      ownerPKH = verificationKeyHash MockWallet.w1
      datum =
        Vesting.VestingParams
          (transPubKeyHash ownerPKH)
          (Vesting.Vesting deadline1 (lovelaceValue 20_000_000))
          (Vesting.Vesting deadline2 (lovelaceValue 40_000_000))
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetTxIn MockWallet.w1 0 $
      lockVesting Defaults.networkId scriptHash datum 60_000_000

  let vs0 =
        VestingState
          { vsInput = txIn
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Advance time to the beggining of the contract validity
  ------------------------------------------------------------------
  setSlot dl1
  ------------------------------------------------------------------
  -- Tx2: withdraw only 20 ADA
  ------------------------------------------------------------------
  vs1 <- withdrawStep Defaults.networkId MockWallet.w1 1 dl1 (dl1 + 100) ownerPKH scriptHash datum vs0 20_000_000
  ------------------------------------------------------------------
  -- Advance time to after the first tranche deadline
  ------------------------------------------------------------------
  setSlot dl2
  ------------------------------------------------------------------
  -- Tx3: withdraw remaining 40 ADA - fee
  ------------------------------------------------------------------
  void $ withdrawStep Defaults.networkId MockWallet.w1 2 dl2 (dl2 + 100) ownerPKH scriptHash datum vs1 38_775_000

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
      validator = C.PlutusScript C.plutusScriptVersion Script.vestingValidatorScript
      scriptHash = C.hashScript validator
      ownerPKH = verificationKeyHash MockWallet.w1
      datum =
        Vesting.VestingParams
          (transPubKeyHash ownerPKH)
          (Vesting.Vesting deadline1 (lovelaceValue 20_000_000))
          (Vesting.Vesting deadline2 (lovelaceValue 40_000_000))
  ------------------------------------------------------------------
  -- Tx1: lock 60 ADA in the vesting script
  ------------------------------------------------------------------
  txIn <-
    submitAndGetTxIn MockWallet.w1 0 $
      lockVesting Defaults.networkId scriptHash datum 60_000_000

  let vs0 =
        VestingState
          { vsInput = txIn
          , vsLocked = 60_000_000
          }
  ------------------------------------------------------------------
  -- Advance time to the beggining of the contract validity
  ------------------------------------------------------------------
  setSlot wSlot
  ------------------------------------------------------------------
  -- Tx2: withdraw only 20 ADA
  ------------------------------------------------------------------
  void $ withdrawStep Defaults.networkId MockWallet.w1 1 lowerSlot upperSlot ownerPKH scriptHash datum vs0 value

-- vts1 <- withdrawStep Defaults.networkId MockWallet.w1 1 lowerSlot upperSlot (verificationKeyHash MockWallet.w2) scriptHash datum vts0 20_000_000
------------------------------------------------------------------
-- Advance time to after the first tranche deadline
------------------------------------------------------------------
-- waitNSlots 10
------------------------------------------------------------------
-- Tx3: withdraw remaining 40 ADA - fee
------------------------------------------------------------------
-- void $ withdrawStep Defaults.networkId MockWallet.w1 2 lowerSlot upperSlot ownerPKH scriptHash datum vts1 30_000_000 --38_775_000
-- void $ withdrawStep Defaults.networkId MockWallet.w1 2 lowerSlot upperSlot (verificationKeyHash MockWallet.w2) scriptHash datum vts1 30_000_000 --38_775_000
