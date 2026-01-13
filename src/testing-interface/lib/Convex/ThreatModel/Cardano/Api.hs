{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}

module Convex.ThreatModel.Cardano.Api where

import Cardano.Api

import Cardano.Ledger.Allegra.Scripts (ValidityInterval (..))
import Cardano.Ledger.Alonzo.Scripts qualified as Ledger
import Cardano.Ledger.Alonzo.TxBody qualified as Ledger
import Cardano.Ledger.Alonzo.TxWits qualified as Ledger
import Cardano.Ledger.Api.Tx.Body qualified as Ledger
import Cardano.Ledger.Conway.Scripts qualified as Conway
import Cardano.Ledger.Conway.TxBody qualified as Conway
import Cardano.Ledger.Keys (WitVKey (..), coerceKeyRole, hashKey)
import Cardano.Slotting.Time (SlotLength, mkSlotLength)
import Data.SOP.NonEmpty (NonEmpty (NonEmptyOne))
import Ouroboros.Consensus.Cardano.Block (CardanoEras, StandardCrypto)
import Ouroboros.Consensus.HardFork.History
import PlutusTx (ToData, toData)

import Data.Either
import Data.Map qualified as Map
import Data.Maybe.Strict
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Word
import GHC.Exts (toList)
import Ouroboros.Consensus.Block (GenesisWindow (..))

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

-- TODO: transactions can fail for different reasons. Sometimes they fail with
-- a "translation error". Translation errors should probably be treated as test
-- failures not as validation failing - it's after all not validation failing!

{- | The result of validating a transaction. In case of failure, it includes a list
  of reasons.
-}
data ValidityReport = ValidityReport
  { valid :: Bool
  , errors :: [String]
  }
  deriving stock (Ord, Eq, Show)

-- NOTE: this function ignores the execution units associated with
-- the scripts in the Tx. That way we don't have to care about computing
-- the right values in the threat model (as this is not our main concern here).
--
-- This also means that if we were to want to deal with execution units in the threat
-- modelling framework we would need to be a bit careful and figure out some abstractions
-- that make it make sense (and check the budgets here).
--
-- Stolen from Hydra
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
  eraHistory = EraHistory (mkInterpreter summary)

  summary :: Summary (CardanoEras StandardCrypto)
  summary =
    Summary . NonEmptyOne $
      EraSummary
        { eraStart = initBound
        , eraEnd = EraUnbounded
        , eraParams =
            EraParams
              { eraEpochSize = epochSize
              , eraSlotLength = slotLength
              , eraSafeZone = UnsafeIndefiniteSafeZone
              , eraGenesisWin = genesisWindow
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
