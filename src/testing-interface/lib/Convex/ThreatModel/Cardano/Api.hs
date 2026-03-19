{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}

module Convex.ThreatModel.Cardano.Api (
  -- * Types
  Era,
  LedgerEra,

  -- * TxOut accessors
  addressOfTxOut,
  valueOfTxOut,
  datumOfTxOut,
  referenceScriptOfTxOut,

  -- * Redeemer and script data
  redeemerOfTxIn,
  recomputeScriptData,
  emptyTxBodyScriptData,
  addScriptData,
  updateRedeemer,
  addMintingRedeemer,
  recomputeScriptDataForMint,
  addDatum,
  toMaryAssetName,

  -- * Address utilities
  paymentCredentialToAddressAny,
  scriptAddressAny,
  keyAddressAny,
  isKeyAddressAny,

  -- * Datum/Redeemer conversion
  toCtxUTxODatum,
  txOutDatum,
  toScriptData,

  -- * Transaction utilities
  dummyTxId,
  makeTxOut,
  txSigners,
  mockWalletHashes,
  detectSigningWallet,
  txRequiredSigners,
  txInputs,
  txReferenceInputs,
  txOutputs,

  -- * Value utilities
  leqValue,
  projectAda,

  -- * Validation
  ValidityReport (..),
  validateTx,
  validateTxM,
  buildMockState,

  -- * Rebalancing
  rebalanceAndSignM,
  rebalanceAndSign,
  updateExecutionUnits,
  updateTxRedeemersWithExUnits,
  updateScriptDataExUnits,
  recalculateScriptIntegrityHash,
  getScriptLanguage,
  getTxFeeCoin,
  setTxFeeCoin,
  setTxOutputsList,
  adjustChangeOutputM,
  adjustChangeOutput,
  replaceAt,

  -- * Validity interval
  convValidityInterval,

  -- * UTxO utilities
  restrictUTxO,

  -- * Coverage
  extractCoverageFromValidationError,
  unescapeHaskellString,
  extractCoverageAnnotations,
) where

import Cardano.Api

import Cardano.Ledger.Allegra.Scripts (ValidityInterval (..))
import Cardano.Ledger.Alonzo.PParams (getLanguageView)
import Cardano.Ledger.Alonzo.Scripts qualified as Ledger
import Cardano.Ledger.Alonzo.Tx (hashScriptIntegrity)
import Cardano.Ledger.Alonzo.TxBody qualified as Ledger
import Cardano.Ledger.Alonzo.TxWits qualified as Ledger
import Cardano.Ledger.Api.Era qualified as Ledger (eraProtVerLow)
import Cardano.Ledger.Api.Tx.Body qualified as Ledger
import Cardano.Ledger.Binary qualified as CBOR
import Cardano.Ledger.Conway.Scripts qualified as Conway
import Cardano.Ledger.Conway.TxBody qualified as Conway
import Cardano.Ledger.Keys (WitVKey (..), coerceKeyRole, hashKey)
import Cardano.Ledger.Mary.Value qualified as Mary
import Cardano.Ledger.Plutus.Language qualified as Plutus
import Cardano.Slotting.Slot ()
import Cardano.Slotting.Time (SlotLength, mkSlotLength)
import Control.Lens ((&), (.~), (^.), _1)
import Data.List (isPrefixOf)

import Convex.CardanoApi.Lenses qualified as L
import Convex.Class (
  ExUnitsError (..),
  MockChainState,
  MonadBlockchain (..),
  MonadMockchain (..),
  ValidationError (..),
  coverageData,
  env,
  getSlot,
  poolState,
 )
import Convex.MockChain (applyTransaction, initialState)
import Convex.NodeParams (NodeParams)
import Convex.Wallet (Wallet)
import Convex.Wallet qualified as Wallet
import Convex.Wallet.MockWallet (mockWallets)
import Data.ByteString.Short qualified as SBS
import Data.Either (isRight)
import Data.Foldable (foldrM)
import Data.Map qualified as Map
import Data.Maybe (listToMaybe, mapMaybe)
import Data.Maybe.Strict
import Data.SOP.NonEmpty (NonEmpty (NonEmptyOne))
import Data.Sequence.Strict qualified as Seq
import Data.Set qualified as Set
import Data.Text qualified as Text
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Word
import GHC.Exts (toList)
import Ouroboros.Consensus.Block (GenesisWindow (..))
import Ouroboros.Consensus.Cardano.Block (CardanoEras, StandardCrypto)
import Ouroboros.Consensus.HardFork.History qualified as History
import PlutusTx (ToData, toData)
import PlutusTx.Coverage (CoverageData, coverageDataFromLogMsg)

type Era = ConwayEra
type LedgerEra = ShelleyLedgerEra Era

addressOfTxOut :: TxOut ctx Era -> AddressAny
addressOfTxOut (TxOut (AddressInEra ShelleyAddressInEra{} addr) _ _ _) = AddressShelley addr
addressOfTxOut (TxOut (AddressInEra ByronAddressInAnyEra{} addr) _ _ _) = AddressByron addr

valueOfTxOut :: TxOut ctx Era -> Value
valueOfTxOut (TxOut _ v _ _) = txOutValueToValue v

-- | Get the datum from a transaction output.
datumOfTxOut :: TxOut ctx Era -> TxOutDatum ctx Era
datumOfTxOut (TxOut _ _ datum _) = datum

referenceScriptOfTxOut :: TxOut ctx Era -> ReferenceScript Era
referenceScriptOfTxOut (TxOut _ _ _ rscript) = rscript

redeemerOfTxIn :: Tx Era -> TxIn -> Maybe ScriptData
redeemerOfTxIn tx txIn = redeemer
 where
  Tx (ShelleyTxBody _ Conway.ConwayTxBody{Conway.ctbSpendInputs = inputs} _ scriptData _ _) _ = tx

  redeemer = case scriptData of
    TxBodyNoScriptData -> Nothing
    TxBodyScriptData _ _ (Ledger.Redeemers rdmrs) ->
      getScriptData . fromAlonzoData . fst <$> Map.lookup (Conway.ConwaySpending idx) rdmrs

  idx = case Ledger.indexOf (Ledger.AsItem (toShelleyTxIn txIn)) inputs of
    SJust idx' -> idx'
    _ -> error "The impossible happened!"

paymentCredentialToAddressAny :: PaymentCredential -> AddressAny
paymentCredentialToAddressAny t =
  AddressShelley $ makeShelleyAddress (Testnet $ NetworkMagic 1) t NoStakeAddress

-- | Construct a script address.
scriptAddressAny :: ScriptHash -> AddressAny
scriptAddressAny = paymentCredentialToAddressAny . PaymentCredentialByScript

-- | Construct a public key address.
keyAddressAny :: Hash PaymentKey -> AddressAny
keyAddressAny = paymentCredentialToAddressAny . PaymentCredentialByKey

-- | Check if an address is a public key address.
isKeyAddressAny :: AddressAny -> Bool
isKeyAddressAny = isKeyAddress . anyAddressInShelleyBasedEra (shelleyBasedEra @Era)

recomputeScriptData
  :: Maybe Word32 -- Index to remove
  -> (Word32 -> Word32)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
recomputeScriptData _ _ TxBodyNoScriptData = TxBodyNoScriptData
recomputeScriptData i f (TxBodyScriptData era dats (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData
    era
    dats
    (Ledger.Redeemers $ Map.mapKeys updatePtr $ Map.filterWithKey idxFilter rdmrs)
 where
  -- updatePtr = Ledger.hoistPlutusPurpose (\(Ledger.AsIx ix) -> Ledger.AsIx (f ix)) -- TODO: replace when hoistPlutusPurpose is available
  updatePtr = \case
    Conway.ConwayMinting (Ledger.AsIx ix) -> Conway.ConwayMinting (Ledger.AsIx (f ix))
    Conway.ConwaySpending (Ledger.AsIx ix) -> Conway.ConwaySpending (Ledger.AsIx (f ix))
    Conway.ConwayRewarding (Ledger.AsIx ix) -> Conway.ConwayRewarding (Ledger.AsIx (f ix))
    Conway.ConwayCertifying (Ledger.AsIx ix) -> Conway.ConwayCertifying (Ledger.AsIx (f ix))
    Conway.ConwayVoting (Ledger.AsIx ix) -> Conway.ConwayVoting (Ledger.AsIx (f ix))
    Conway.ConwayProposing (Ledger.AsIx ix) -> Conway.ConwayProposing (Ledger.AsIx (f ix))
  idxFilter (Conway.ConwaySpending (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter (Conway.ConwayMinting (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter (Conway.ConwayCertifying (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter (Conway.ConwayRewarding (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter (Conway.ConwayVoting (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter (Conway.ConwayProposing (Ledger.AsIx idx)) _ = Just idx /= i

emptyTxBodyScriptData :: TxBodyScriptData Era
emptyTxBodyScriptData = TxBodyScriptData AlonzoEraOnwardsConway (Ledger.TxDats mempty) (Ledger.Redeemers mempty)

addScriptData
  :: Word32
  -> Ledger.Data (ShelleyLedgerEra Era)
  -> (Ledger.Data (ShelleyLedgerEra Era), Ledger.ExUnits)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
addScriptData ix dat rdmr TxBodyNoScriptData = addScriptData ix dat rdmr emptyTxBodyScriptData
addScriptData ix dat rdmr (TxBodyScriptData era (Ledger.TxDats dats) (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData
    era
    (Ledger.TxDats $ Map.insert (Ledger.hashData dat) dat dats)
    (Ledger.Redeemers $ Map.insert (Conway.ConwaySpending (Ledger.AsIx ix)) rdmr rdmrs)

{- | Update only the redeemer for a spending input (does not modify TxDats)
Use this when the original UTxO has an inline datum to avoid adding orphaned datums
-}
updateRedeemer
  :: Word32
  -> (Ledger.Data (ShelleyLedgerEra Era), Ledger.ExUnits)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
updateRedeemer ix rdmr TxBodyNoScriptData = updateRedeemer ix rdmr emptyTxBodyScriptData
updateRedeemer ix rdmr (TxBodyScriptData era dats (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData
    era
    dats
    (Ledger.Redeemers $ Map.insert (Conway.ConwaySpending (Ledger.AsIx ix)) rdmr rdmrs)

-- | Add a minting redeemer to the script data (no datum needed for minting)
addMintingRedeemer
  :: Word32
  -> (Ledger.Data (ShelleyLedgerEra Era), Ledger.ExUnits)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
addMintingRedeemer _ _ TxBodyNoScriptData = addMintingRedeemer 0 (error "no redeemer", Ledger.ExUnits 0 0) emptyTxBodyScriptData
addMintingRedeemer ix rdmr (TxBodyScriptData era dats (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData
    era
    dats
    (Ledger.Redeemers $ Map.insert (Conway.ConwayMinting (Ledger.AsIx ix)) rdmr rdmrs)

-- | Like recomputeScriptData but only updates minting redeemer indices
recomputeScriptDataForMint
  :: Maybe Word32 -- Index to remove
  -> (Word32 -> Word32)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
recomputeScriptDataForMint _ _ TxBodyNoScriptData = TxBodyNoScriptData
recomputeScriptDataForMint i f (TxBodyScriptData era dats (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData
    era
    dats
    (Ledger.Redeemers $ Map.mapKeys updatePtr $ Map.filterWithKey idxFilter rdmrs)
 where
  updatePtr = \case
    Conway.ConwayMinting (Ledger.AsIx ix) -> Conway.ConwayMinting (Ledger.AsIx (f ix))
    other -> other -- Don't modify non-minting redeemers
  idxFilter (Conway.ConwayMinting (Ledger.AsIx idx)) _ = Just idx /= i
  idxFilter _ _ = True -- Keep all non-minting redeemers

-- | Convert cardano-api AssetName to ledger Mary.AssetName
toMaryAssetName :: AssetName -> Mary.AssetName
toMaryAssetName an = Mary.AssetName $ SBS.toShort $ serialiseToRawBytes an

addDatum
  :: Ledger.Data (ShelleyLedgerEra Era)
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
addDatum dat TxBodyNoScriptData = addDatum dat emptyTxBodyScriptData
addDatum dat (TxBodyScriptData era (Ledger.TxDats dats) rdmrs) =
  TxBodyScriptData
    era
    (Ledger.TxDats $ Map.insert (Ledger.hashData dat) dat dats)
    rdmrs

toCtxUTxODatum :: TxOutDatum CtxTx Era -> TxOutDatum CtxUTxO Era
toCtxUTxODatum d = case d of
  TxOutDatumNone -> TxOutDatumNone
  TxOutDatumHash s h -> TxOutDatumHash s h
  TxOutDatumInline s sd -> TxOutDatumInline s sd
  TxOutSupplementalDatum s _sd -> TxOutDatumHash s (hashScriptDataBytes _sd)

-- | Convert ScriptData to a `Test.QuickCheck.ContractModel.ThreatModel.Datum`.
txOutDatum :: ScriptData -> TxOutDatum CtxTx Era
txOutDatum d = TxOutDatumInline BabbageEraOnwardsConway (unsafeHashableScriptData d)

{- | Convert a Haskell value to ScriptData for use as a
`Test.QuickCheck.ContractModel.ThreatModel.Redeemer` or convert to a
`Test.QuickCheck.ContractModel.ThreatModel.Datum` with `txOutDatum`.
-}
toScriptData :: (ToData a) => a -> ScriptData
toScriptData = fromPlutusData . toData

-- | Used for new inputs.
dummyTxId :: TxId
dummyTxId =
  fromShelleyTxId $
    Ledger.txIdTxBody @LedgerEra $
      Ledger.mkBasicTxBody

makeTxOut :: AddressAny -> Value -> TxOutDatum CtxTx Era -> ReferenceScript Era -> TxOut CtxUTxO Era
makeTxOut addr value datum refScript =
  toCtxUTxOTxOut $
    TxOut
      (anyAddressInShelleyBasedEra shelleyBasedEra addr)
      (TxOutValueShelleyBased shelleyBasedEra (toMaryValue value))
      datum
      refScript

txSigners :: Tx Era -> [Hash PaymentKey]
txSigners (Tx _ wits) = [toHash wit | ShelleyKeyWitness _ (WitVKey wit _) <- wits]
 where
  toHash =
    PaymentKeyHash
      . hashKey
      . coerceKeyRole

mockWalletHashes :: [(Hash PaymentKey, Wallet)]
mockWalletHashes = map (\w -> (Wallet.verificationKeyHash w, w)) mockWallets

{- | Detect which mock wallet signed a transaction by examining its witnesses.
Returns an error message if no known mock wallet is found among the signers.
-}
detectSigningWallet :: Tx Era -> Either String Wallet
detectSigningWallet tx =
  case txSigners tx of
    [] -> Left "Transaction has no signers — cannot determine wallet for threat model"
    signers ->
      case mapMaybe (\h -> lookup h mockWalletHashes) signers of
        (w : _) -> Right w
        [] -> Left "Transaction signers do not match any known mock wallet"

-- | Get the required signers from the transaction body (not witnesses).
txRequiredSigners :: Tx Era -> [Hash PaymentKey]
txRequiredSigners (Tx (ShelleyTxBody _ body _ _ _ _) _) =
  map (PaymentKeyHash . coerceKeyRole) . Set.toList $ Conway.ctbReqSignerHashes body

txInputs :: Tx Era -> [TxIn]
txInputs tx = map fst $ txIns body
 where
  body = getTxBodyContent $ getTxBody tx

txReferenceInputs :: Tx Era -> [TxIn]
txReferenceInputs tx =
  case txInsReference body of
    TxInsReferenceNone -> []
    TxInsReference _ txins _ -> txins
 where
  body = getTxBodyContent $ getTxBody tx

txOutputs :: Tx Era -> [TxOut CtxTx Era]
txOutputs tx = txOuts body
 where
  body = getTxBodyContent $ getTxBody tx

-- | Check if a value is less or equal than another value.
leqValue :: Value -> Value -> Bool
leqValue v v' = all ((<= 0) . snd) (toList $ v <> negateValue v')

-- | Keep only the Ada part of a value.
projectAda :: Value -> Value
projectAda = lovelaceToValue . selectLovelace

{- | The result of validating a transaction. In case of failure, it includes a list
  of reasons.
-}
data ValidityReport = ValidityReport
  { valid :: Bool
  , errors :: [String]
  }
  deriving stock (Ord, Eq, Show)

{- | Validate a transaction using Phase 2 (script execution) validation only.

This uses evaluateTransactionExecutionUnits to check if Plutus scripts would
accept or reject the transaction. It does NOT validate Phase 1 ledger rules
(fees, signatures, value preservation, etc.) because threat model modifications
alter the transaction body, invalidating signatures and fee calculations.

The purpose of threat models is to test script logic, not transaction construction.
-}
validateTx :: LedgerProtocolParameters Era -> Tx Era -> UTxO Era -> ValidityReport
validateTx pparams tx utxos =
  ValidityReport
    (all isRight (Map.elems report))
    [show e | Left e <- Map.elems report]
 where
  report =
    evaluateTransactionExecutionUnits
      ConwayEra
      systemStart
      (toLedgerEpochInfo eraHistory)
      pparams
      utxos
      (getTxBody tx)

  eraHistory :: EraHistory
  eraHistory = EraHistory (History.mkInterpreter summary)

  summary :: History.Summary (CardanoEras StandardCrypto)
  summary =
    History.Summary . NonEmptyOne $
      History.EraSummary
        { History.eraStart = History.initBound
        , History.eraEnd = History.EraUnbounded
        , History.eraParams =
            History.EraParams
              { History.eraEpochSize = epochSize
              , History.eraSlotLength = slotLength
              , History.eraSafeZone = History.UnsafeIndefiniteSafeZone
              , History.eraGenesisWin = genesisWindow
              }
        }

  epochSize :: EpochSize
  epochSize = EpochSize 100

  slotLength :: SlotLength
  slotLength = mkSlotLength 1

  systemStart :: SystemStart
  systemStart = SystemStart $ posixSecondsToUTCTime 0

  genesisWindow :: GenesisWindow
  genesisWindow = GenesisWindow 10

-- | Keep only UTxOs mentioned in the given transaction.
restrictUTxO :: Tx Era -> UTxO Era -> UTxO Era
restrictUTxO tx (UTxO utxo) =
  UTxO $
    Map.filterWithKey
      ( \k _ ->
          k `elem` map fst (txIns body)
            || k `elem` toInputList (txInsReference body)
      )
      utxo
 where
  body = getTxBodyContent $ getTxBody tx
  toInputList (TxInsReference _ ins _) = ins
  toInputList _ = []

convValidityInterval
  :: (TxValidityLowerBound era, TxValidityUpperBound era)
  -> ValidityInterval
convValidityInterval (lowerBound, upperBound) =
  ValidityInterval
    { invalidBefore = case lowerBound of
        TxValidityNoLowerBound -> SNothing
        TxValidityLowerBound _ s -> SJust s
    , invalidHereafter = case upperBound of
        TxValidityUpperBound _ Nothing -> SNothing
        TxValidityUpperBound _ (Just s) -> SJust s
    }

-- | Build a MockChainState from NodeParams, slot, and UTxO for validation
buildMockState
  :: NodeParams Era
  -> SlotNo
  -> UTxO Era
  -> MockChainState Era
buildMockState params slot utxo =
  initialState params
    & env . L.slot .~ slot
    & poolState . L.utxoState . L._UTxOState . _1 .~ toLedgerUTxO shelleyBasedEra utxo

{- | Validate a transaction with full Phase 1 + Phase 2 validation inside MockchainT.

This uses 'applyTransaction' which performs complete ledger validation including:
- Fee adequacy
- Signature verification
- UTxO existence
- Value preservation
- Validity intervals
- Collateral requirements
- Script execution (Phase 2)
-}
validateTxM
  :: (MonadMockchain Era m)
  => NodeParams Era
  -> Tx Era
  -> UTxO Era
  -> m (ValidityReport, CoverageData)
validateTxM params tx utxo = do
  slot <- getSlot
  let mockState = buildMockState params slot utxo
  pure $ case applyTransaction params mockState tx of
    Left (VExUnits (Phase2Error (ScriptErrorEvaluationFailed DebugPlutusFailure{dpfEvaluationError, dpfExecutionLogs}))) ->
      (ValidityReport False [show dpfEvaluationError], foldMap (coverageDataFromLogMsg . Text.unpack) dpfExecutionLogs)
    Left err -> (ValidityReport False [show err], mempty)
    Right (state', _) -> (ValidityReport True [], state' ^. coverageData)

{- | Re-balance fees, recalculate execution units, and re-sign a modified transaction.

After applying TxModifier operations, the transaction body changes which:
1. Invalidates the original signatures (body hash changed)
2. May require different fees (outputs changed)
3. May have invalid execution units (for added scripts)

This function:
1. Recalculates execution units for all scripts
2. Calculates the new required fee
3. Adjusts the change output (last output to wallet address) to compensate
4. Re-signs the transaction with the wallet's key
-}
rebalanceAndSignM
  :: (MonadMockchain Era m, MonadFail m)
  => Wallet
  -> Tx Era
  -> UTxO Era
  -> m (Tx Era)
rebalanceAndSignM wallet tx utxo = do
  result <- rebalanceAndSign wallet tx utxo
  case result of
    Left err -> fail err
    Right signedTx -> pure signedTx

{- | Like 'rebalanceAndSign' but returns Either instead of using MonadFail.

This is useful for threat model execution where we want to handle rebalancing
failures (e.g., "No change output found") as skipped tests rather than errors.
-}
rebalanceAndSign
  :: (MonadMockchain Era m)
  => Wallet
  -> Tx Era
  -> UTxO Era
  -> m (Either String (Tx Era))
rebalanceAndSign wallet tx utxo = do
  pparams <- Convex.Class.queryProtocolParameters
  networkId <- Convex.Class.queryNetworkId
  systemStart <- Convex.Class.querySystemStart
  eraHistory <- Convex.Class.queryEraHistory

  let walletAddr = Wallet.addressInEra networkId wallet

  -- First, recalculate execution units for all scripts in the transaction
  -- This is necessary because TxModifier may add scripts with ExecutionUnits 0 0
  let txWithUpdatedExUnits = updateExecutionUnits pparams systemStart eraHistory utxo tx

  -- Get the current fee from the transaction (from the ledger body)
  let currentFee = getTxFeeCoin txWithUpdatedExUnits

  -- Create a temp tx with max fee to calculate the actual required fee
  let maxFee = Coin (2 ^ (32 :: Integer) - 1)
      tempTx = setTxFeeCoin maxFee txWithUpdatedExUnits
      Tx tempBody _ = tempTx
      newFee =
        calculateMinTxFee
          shelleyBasedEra
          (unLedgerProtocolParameters pparams)
          utxo
          tempBody
          1

  -- Calculate fee difference
  let feeDiff = newFee - currentFee -- positive = fee increased

  -- Adjust the change output and set the new fee
  let currentOuts = txOutputs txWithUpdatedExUnits
  case adjustChangeOutput walletAddr feeDiff currentOuts of
    Left err -> pure (Left err)
    Right adjustedOutputs -> do
      -- Apply the changes: new fee and adjusted outputs
      let modifiedTx = setTxOutputsList adjustedOutputs $ setTxFeeCoin newFee txWithUpdatedExUnits

      -- Recalculate script integrity hash (after updating execution units)
      let finalTx = recalculateScriptIntegrityHash pparams modifiedTx

      -- Re-sign (strip old signatures and add new one)
      let Tx finalBody _ = finalTx
          unsignedTx = makeSignedTransaction [] finalBody
          signers = txSigners tx
          sign hash tx' = case lookup hash mockWalletHashes of
            Just w -> Right $ Wallet.signTx w tx'
            Nothing -> Left "Transaction was signed by an unknown wallet"
      pure $ foldrM sign unsignedTx signers

{- | Update execution units in a transaction by evaluating all scripts.

This computes the actual execution units required for each script and updates
the redeemers in the transaction with those values. This is necessary because
TxModifier operations like addPlutusScriptMint use ExecutionUnits 0 0 as
placeholders.
-}
updateExecutionUnits
  :: LedgerProtocolParameters Era
  -> SystemStart
  -> EraHistory
  -> UTxO Era
  -> Tx Era
  -> Tx Era
updateExecutionUnits pparams systemStart eraHistory utxo tx =
  let exUnitsMap =
        evaluateTransactionExecutionUnits
          ConwayEra
          systemStart
          (toLedgerEpochInfo eraHistory)
          pparams
          utxo
          (getTxBody tx)
      -- Extract only successful execution unit results
      successfulExUnits =
        Map.mapMaybe
          ( \case
              Right (_, exUnits) -> Just exUnits
              Left _ -> Nothing
          )
          exUnitsMap
   in updateTxRedeemersWithExUnits successfulExUnits tx

{- | Update the execution units in a transaction's redeemers.

This function takes a map from ScriptWitnessIndex to ExecutionUnits and updates
the corresponding redeemers in the transaction.
-}
updateTxRedeemersWithExUnits
  :: Map.Map ScriptWitnessIndex ExecutionUnits
  -> Tx Era
  -> Tx Era
updateTxRedeemersWithExUnits exUnitsMap (Tx (ShelleyTxBody era body scripts scriptData auxData validity) wits) =
  let scriptData' = updateScriptDataExUnits exUnitsMap scriptData
   in Tx (ShelleyTxBody era body scripts scriptData' auxData validity) wits

-- | Update execution units in TxBodyScriptData based on ScriptWitnessIndex map.
updateScriptDataExUnits
  :: Map.Map ScriptWitnessIndex ExecutionUnits
  -> TxBodyScriptData Era
  -> TxBodyScriptData Era
updateScriptDataExUnits _ TxBodyNoScriptData = TxBodyNoScriptData
updateScriptDataExUnits exUnitsMap (TxBodyScriptData eraWit dats (Ledger.Redeemers rdmrs)) =
  TxBodyScriptData eraWit dats (Ledger.Redeemers updatedRdmrs)
 where
  updatedRdmrs = Map.mapWithKey updateRedeemer' rdmrs

  updateRedeemer' :: Conway.ConwayPlutusPurpose Ledger.AsIx LedgerEra -> (Ledger.Data LedgerEra, Ledger.ExUnits) -> (Ledger.Data LedgerEra, Ledger.ExUnits)
  updateRedeemer' purpose (dat, _oldExUnits) =
    case purposeToScriptWitnessIndex purpose of
      Just idx -> case Map.lookup idx exUnitsMap of
        Just newExUnits -> (dat, toAlonzoExUnits newExUnits)
        Nothing -> (dat, _oldExUnits) -- Keep old if not in map
      Nothing -> (dat, _oldExUnits)

  -- Convert Conway purpose to cardano-api ScriptWitnessIndex
  purposeToScriptWitnessIndex :: Conway.ConwayPlutusPurpose Ledger.AsIx LedgerEra -> Maybe ScriptWitnessIndex
  purposeToScriptWitnessIndex (Conway.ConwaySpending (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexTxIn ix
  purposeToScriptWitnessIndex (Conway.ConwayMinting (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexMint ix
  purposeToScriptWitnessIndex (Conway.ConwayRewarding (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexWithdrawal ix
  purposeToScriptWitnessIndex (Conway.ConwayCertifying (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexCertificate ix
  purposeToScriptWitnessIndex (Conway.ConwayVoting (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexVoting ix
  purposeToScriptWitnessIndex (Conway.ConwayProposing (Ledger.AsIx ix)) = Just $ ScriptWitnessIndexProposing ix

{- | Recalculate and update the script integrity hash in a transaction.

The script integrity hash commits to:
- The redeemers in the transaction
- The datums in the witness set
- The cost models for languages used (from protocol parameters)

After modifying a transaction (adding/removing inputs, changing redeemers/datums),
this hash becomes stale and must be recalculated.
-}
recalculateScriptIntegrityHash :: LedgerProtocolParameters Era -> Tx Era -> Tx Era
recalculateScriptIntegrityHash pparams (Tx (ShelleyTxBody era body scripts scriptData auxData validity) wits) =
  let
    -- Extract redeemers and datums from scriptData
    (redeemers, datums) = case scriptData of
      TxBodyNoScriptData -> (Ledger.Redeemers mempty, Ledger.TxDats mempty)
      TxBodyScriptData _ dats rdmrs -> (rdmrs, dats)

    -- Get the protocol parameters
    pp = unLedgerProtocolParameters pparams

    -- Determine which languages are used by examining the scripts in the transaction
    usedLangs =
      Set.fromList
        [ lang
        | script <- scripts
        , Just lang <- [getScriptLanguage script]
        ]

    -- Get LangDepView for each used language
    langs =
      Set.fromList
        [ getLanguageView pp lang
        | lang <- Set.toList usedLangs
        ]

    -- Compute new script integrity hash
    newHash = hashScriptIntegrity langs redeemers datums

    -- Update the body with new hash
    body' = body{Conway.ctbScriptIntegrityHash = newHash}
   in
    Tx (ShelleyTxBody era body' scripts scriptData auxData validity) wits

-- | Extract the Plutus language from a ledger script, if it's a Plutus script
getScriptLanguage :: Ledger.AlonzoScript LedgerEra -> Maybe Plutus.Language
getScriptLanguage script = case script of
  Ledger.TimelockScript{} -> Nothing
  Ledger.PlutusScript ps -> Just $ Ledger.plutusScriptLanguage ps

-- | Get the fee from a transaction
getTxFeeCoin :: Tx Era -> Coin
getTxFeeCoin (Tx (ShelleyTxBody _ body _ _ _ _) _) = Conway.ctbTxfee body

-- | Set the fee in a transaction
setTxFeeCoin :: Coin -> Tx Era -> Tx Era
setTxFeeCoin fee (Tx (ShelleyTxBody era body scripts scriptData auxData validity) wits) =
  Tx (ShelleyTxBody era body{Conway.ctbTxfee = fee} scripts scriptData auxData validity) wits

-- | Set transaction outputs (helper that works at the Tx level)
setTxOutputsList :: [TxOut CtxTx Era] -> Tx Era -> Tx Era
setTxOutputsList newOuts (Tx (ShelleyTxBody era body scripts scriptData auxData validity) wits) =
  let newOutsSeq =
        Seq.fromList
          [ CBOR.mkSized
              (Ledger.eraProtVerLow @LedgerEra)
              (toShelleyTxOut shelleyBasedEra (toCtxUTxOTxOut out))
          | out <- newOuts
          ]
      body' = body{Conway.ctbOutputs = newOutsSeq}
   in Tx (ShelleyTxBody era body' scripts scriptData auxData validity) wits

{- | Adjust the last output going to wallet address by fee difference.

If fee increased, we subtract from the change output.
If fee decreased, we add to the change output.
-}
adjustChangeOutputM
  :: (MonadFail m)
  => AddressInEra Era
  -- ^ Wallet address to find change output
  -> Coin
  -- ^ Fee difference (positive = fee increased)
  -> [TxOut CtxTx Era]
  -- ^ Transaction outputs
  -> m [TxOut CtxTx Era]
adjustChangeOutputM walletAddr feeDiff outputs =
  case adjustChangeOutput walletAddr feeDiff outputs of
    Left err -> fail err
    Right result -> pure result

-- | Like 'adjustChangeOutput' but returns Either instead of using MonadFail.
adjustChangeOutput
  :: AddressInEra Era
  -- ^ Wallet address to find change output
  -> Coin
  -- ^ Fee difference (positive = fee increased)
  -> [TxOut CtxTx Era]
  -- ^ Transaction outputs
  -> Either String [TxOut CtxTx Era]
adjustChangeOutput walletAddr (Coin feeDiff) outputs = do
  -- Find last output to wallet address
  let indexed = zip [0 ..] outputs
      walletOutputs =
        [ (i, o)
        | (i, o@(TxOut addr _ _ _)) <- indexed
        , addr == walletAddr
        ]
  case listToMaybe (reverse walletOutputs) of
    Nothing -> Left "No change output found to wallet address"
    Just (idx, TxOut addr val datum refScript) -> do
      let Coin oldAda = txOutValueToLovelace val
          newAda = oldAda - feeDiff -- subtract fee increase (or add fee decrease)
      if newAda < 0
        then Left "Change output cannot cover fee increase"
        else do
          let newLovelace = Coin newAda
              -- Preserve non-Ada assets in the value
              oldValue = txOutValueToValue val
              newValue = oldValue <> negateValue (lovelaceToValue (Coin oldAda)) <> lovelaceToValue newLovelace
              newVal = TxOutValueShelleyBased shelleyBasedEra (toMaryValue newValue)
              newOutput = TxOut addr newVal datum refScript
          Right $ replaceAt idx newOutput outputs

-- | Replace element at index in a list
replaceAt :: Int -> a -> [a] -> [a]
replaceAt _ _ [] = []
replaceAt 0 x (_ : xs) = x : xs
replaceAt n x (y : ys) = y : replaceAt (n - 1) x ys

{- | Extract coverage data from a ValidationError string containing CovLoc annotations.
Handles the format found in Phase2 script evaluation errors where coverage
annotations appear as "CoverLocation (CovLoc {...})" or "CoverBool (CovLoc {...}) Bool"
-}
extractCoverageFromValidationError :: String -> CoverageData
extractCoverageFromValidationError errStr =
  mconcat $ map (coverageDataFromLogMsg . unescapeHaskellString) $ extractCoverageAnnotations errStr

-- | Unescape common Haskell string escapes (backslash-quote to quote, backslash-backslash to backslash)
unescapeHaskellString :: String -> String
unescapeHaskellString [] = []
unescapeHaskellString ('\\' : '"' : xs) = '"' : unescapeHaskellString xs
unescapeHaskellString ('\\' : '\\' : xs) = '\\' : unescapeHaskellString xs
unescapeHaskellString (x : xs) = x : unescapeHaskellString xs

{- | Extract all "CoverLocation (...)" and "CoverBool (...)" substrings from text.
Uses bracket counting to properly match nested parentheses.
-}
extractCoverageAnnotations :: String -> [String]
extractCoverageAnnotations [] = []
extractCoverageAnnotations s = case findCoverageStart s of
  Nothing -> []
  Just (prefix, rest) ->
    case extractBalancedParens rest of
      Nothing -> extractCoverageAnnotations (drop 1 s) -- skip and continue
      Just (content, remaining) ->
        (prefix ++ "(" ++ content ++ ")") : extractCoverageAnnotations remaining
 where
  -- Find "CoverLocation (" or "CoverBool (" prefix
  -- Returns the prefix and rest of string starting with '('
  -- "CoverLocation " is 14 chars, "CoverBool " is 10 chars
  findCoverageStart :: String -> Maybe (String, String)
  findCoverageStart [] = Nothing
  findCoverageStart str
    | "CoverLocation (" `isPrefixOf` str = Just ("CoverLocation ", drop 14 str) -- keep "(CovLoc..."
    | "CoverBool (" `isPrefixOf` str = Just ("CoverBool ", drop 10 str) -- keep "(CovLoc..."
    | otherwise = findCoverageStart (drop 1 str)

  -- Extract content within balanced parentheses
  -- Expects the string to start with '(' and returns content between matching parens
  extractBalancedParens :: String -> Maybe (String, String)
  extractBalancedParens ('(' : xs) = go' 1 [] xs
   where
    go' :: Integer -> [Char] -> [Char] -> Maybe ([Char], [Char])
    go' _ _ [] = Nothing
    go' n acc (c : cs)
      | c == '(' = go' (n + 1) (c : acc) cs
      | c == ')' =
          if n == 1
            then Just (reverse acc, cs)
            else go' (n - 1) (c : acc) cs
      | otherwise = go' n (c : acc) cs
  extractBalancedParens _ = Nothing
