{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Replace case with fromMaybe" #-}

module Utils.VestingUtils (
  -- * Unit Testing Functions
  lockVestingTest,
  lockTwiceVestingTest,
  retrieveFundsTest,
  retrieveFundsInSteps,
  lockTwiceAndRetrieveFundsTest,

  -- * Property-Based Testing Functions
  lockVestingPBT,
  retrieveFundsPBT,

  -- * Types
  VestingState (..),
) where

import Control.Monad (forM_, void, when)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (
  TxBuilder,
  addRequiredSignature,
  addValidityRangeSlots,
  execBuildTx,
 )

import Cardano.Api (SlotNo)
import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Contracts.Vesting qualified as Vesting
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  MonadBlockchain (..),
  MonadMockchain,
  setSlot,
 )
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (utxoSet)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.Utils (inBabbage, slotToUtcTime, utcTimeToPosixTime)
import Convex.Utxos (toApiUtxo)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import PlutusLedgerApi.V1 (POSIXTime, lovelaceValue)
import Scripts.VestingScript qualified as Script

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

-------------------------------------------------------------------------------
-- Property-Based Testing Functions
-------------------------------------------------------------------------------

-- | Lock funds in vesting contract for property-based testing.
lockVestingPBT
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era)
  => C.SlotNo
  -- ^ Deadline for first tranche
  -> Wallet
  -- ^ Wallet funding the vesting (not necessarily the owner)
  -> C.Lovelace
  -- ^ Amount to lock
  -> m ()
lockVestingPBT dl w amt = inBabbage @era $ do
  deadline <- slotToPosixTime dl
  -- Owner is always w1 in our tests
  let ownerPKH = verificationKeyHash MockWallet.w1
      params = mkVestingParams ownerPKH deadline 20_000_000 (deadline + 10_000) 40_000_000

  void $
    submitAndGetScriptTxIn w (mkScriptHash params) $
      lockVesting (mkScriptHash params) amt

-- | Retrieve funds from vesting contract for property-based testing.
retrieveFundsPBT
  :: forall era m
   . (MonadMockchain era m, MonadError (BalanceTxError era) m, MonadFail m, C.IsBabbageBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => Vesting.VestingParams
  -- ^ Vesting parameters
  -> C.SlotNo
  -- ^ Lower validity bound
  -> C.SlotNo
  -- ^ Upper validity bound
  -> C.SlotNo
  -- ^ Current slot (set chain to this)
  -> C.Lovelace
  -- ^ Amount to withdraw
  -> m ()
retrieveFundsPBT params lowerSlot upperSlot curSlot amt = inBabbage @era $ do
  let scriptHash = mkScriptHash params
      ownerPKH = verificationKeyHash MockWallet.w1

  -- Set blockchain time
  setSlot curSlot

  -- Query blockchain for vesting UTxOs
  utxos <- findVestingUtxos scriptHash

  when (null utxos) $ fail "No vesting UTxOs found on chain"

  -- Calculate total locked amount from UTxOs
  let txIns = map fst utxos
      totalLocked =
        sum
          [ C.txOutValueToLovelace val
          | (_, C.TxOut _ val _ _) <- utxos
          ]

  let vestingState =
        VestingState
          { vsInputs = txIns
          , vsLocked = totalLocked
          }

  void $ withdrawStep MockWallet.w1 lowerSlot upperSlot ownerPKH params vestingState amt

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
  => SlotNo
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
