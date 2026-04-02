{-# LANGUAGE GADTs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Replace case with fromMaybe" #-}

module Vesting.Utils (
  -- * Types
  VestingState (..),
  VestingConfig (..),

  -- * Helpers for building transactions
  mkVestingParams,
  mkScriptHash,
  slotToPosixTime,
  lockVesting,
  withdrawVesting,
  submitAndGetScriptTxIn,
  findVestingUtxos,
  withdrawStep,
) where

import Control.Monad (forM_)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (
  TxBuilder,
  addRequiredSignature,
  addValidityRangeSlots,
  execBuildTx,
 )

import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  MonadBlockchain (queryEraHistory, querySystemStart),
  MonadMockchain,
 )
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (utxoSet)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Utxos (toApiUtxo)
import Convex.Wallet (Wallet)
import PlutusLedgerApi.V1 (POSIXTime, lovelaceValue)
import Vesting.Scripts qualified as Script
import Vesting.Validator qualified as Vesting

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

-- | State tracking UTxOs locked in vesting contract
data VestingState = VestingState
  { vsInputs :: [C.TxIn]
  -- ^ UTxOs to spend
  , vsLocked :: C.Lovelace
  -- ^ Total amount locked
  }
  deriving (Show, Eq)

-- | Configuration for creating vesting contracts
data VestingConfig = VestingConfig
  { vcOwner :: C.Hash C.PaymentKey
  -- ^ Beneficiary who can withdraw
  , vcTranche1Slot :: C.SlotNo
  -- ^ When first tranche unlocks
  , vcTranche1Amount :: C.Lovelace
  -- ^ Amount in first tranche
  , vcTranche2Slot :: C.SlotNo
  -- ^ When second tranche unlocks
  , vcTranche2Amount :: C.Lovelace
  -- ^ Amount in second tranche
  }
  deriving (Show, Eq)

-------------------------------------------------------------------------------
-- Core Building Blocks
-------------------------------------------------------------------------------

-- | Create VestingParams
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

-- | Get script hash from vesting parameters.
mkScriptHash :: Vesting.VestingParams -> C.ScriptHash
mkScriptHash params =
  let validator = C.PlutusScript C.plutusScriptVersion (Script.vestingValidatorScript params)
   in C.hashScript validator

-- | Convert SlotNo to POSIXTime (common operation extracted).
slotToPosixTime
  :: (MonadMockchain era m, MonadFail m)
  => C.SlotNo
  -> m POSIXTime
slotToPosixTime slot = do
  eraHist <- queryEraHistory
  sysStart <- querySystemStart
  utcTime <- either fail pure $ slotToUtcTime eraHist sysStart slot
  pure $ utcTimeToPosixTime utcTime

-------------------------------------------------------------------------------
-- Transaction Building Blocks
-------------------------------------------------------------------------------

-- | Build transaction to lock funds in vesting script.
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

-- | Build transaction to withdraw from vesting script.
withdrawVesting
  :: forall era
   . (C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => C.SlotNo
  -- ^ Lower validity bound
  -> C.SlotNo
  -- ^ Upper validity bound
  -> C.Hash C.PaymentKey
  -- ^ Owner signature
  -> Vesting.VestingParams
  -- ^ Vesting parameters
  -> VestingState
  -- ^ Current state
  -> C.Lovelace
  -- ^ Amount to withdraw
  -> TxBuilder era
withdrawVesting lower upper pkh vestingParams vtState amt =
  execBuildTx $ do
    -- Here is where we set the validity range for the transaction
    -- It needs to be within the vesting schedule, i.e., the lower validity should be after the deadlines
    -- For each transaction, we update the lower validity to be after the previous one, considering the current slot
    addValidityRangeSlots lower upper
    addRequiredSignature pkh

    -- Consume ALL script UTXO
    forM_ (vsInputs vtState) $ \txIn ->
      BuildTx.spendPlutusInlineDatum txIn (Script.vestingValidatorScript vestingParams) ()
    -- Pay withdrawal amount to owner
    BuildTx.payToPublicKey Defaults.networkId pkh (C.lovelaceToValue amt)
    -- Return remaining to the script
    let remaining = vsLocked vtState - amt
    BuildTx.payToScriptInlineDatum
      Defaults.networkId
      (mkScriptHash vestingParams)
      ()
      C.NoStakeAddress
      (C.lovelaceToValue remaining)

-------------------------------------------------------------------------------
-- Blockchain Interaction Helpers
-------------------------------------------------------------------------------

-- | Submit transaction and extract the script output TxIn.
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
  let txBody = C.getTxBody tx
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
  isScriptAddress (C.AddressInEra _ (C.ShelleyAddress _ (ScriptHashObj h) _)) =
    h == C.toShelleyScriptHash scriptHash
  isScriptAddress _ = False

-- | Query blockchain for all UTxOs locked in a vesting script.
findVestingUtxos
  :: forall era m
   . (MonadMockchain era m, MonadFail m, C.IsBabbageBasedEra era)
  => C.ScriptHash -> m [(C.TxIn, C.TxOut C.CtxUTxO era)]
findVestingUtxos scriptHash = do
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

-- | Execute a withdrawal step and return updated state.
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
