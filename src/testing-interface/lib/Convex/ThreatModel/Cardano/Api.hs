{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

module Convex.ThreatModel.Cardano.Api where

import Cardano.Api

import Cardano.Ledger.Allegra.Scripts (ValidityInterval (..))
import Cardano.Ledger.Alonzo.Scripts qualified as Ledger
import Cardano.Ledger.Alonzo.TxBody qualified as Ledger
import Cardano.Ledger.Alonzo.TxWits qualified as Ledger
import Cardano.Ledger.Api.Era qualified as Ledger (eraProtVerLow)
import Cardano.Ledger.Api.Tx.Body qualified as Ledger
import Cardano.Ledger.Binary qualified as CBOR
import Cardano.Ledger.Conway.Scripts qualified as Conway
import Cardano.Ledger.Conway.TxBody qualified as Conway
import Cardano.Ledger.Keys (WitVKey (..), coerceKeyRole, hashKey)
import Cardano.Slotting.Slot ()
import Cardano.Slotting.Time (SlotLength, mkSlotLength)
import Control.Lens ((&), (.~), _1)
import Control.Monad (when)
import Convex.CardanoApi.Lenses qualified as L
import Convex.Class (
  MockChainState,
  MonadBlockchain (..),
  MonadMockchain (..),
  env,
  getSlot,
  poolState,
 )
import Convex.MockChain (applyTransaction, initialState)
import Convex.NodeParams (NodeParams)
import Convex.Wallet (Wallet)
import Convex.Wallet qualified as Wallet
import Data.Either (isRight)
import Data.Map qualified as Map
import Data.Maybe (listToMaybe)
import Data.Maybe.Strict
import Data.SOP.NonEmpty (NonEmpty (NonEmptyOne))
import Data.Sequence.Strict qualified as Seq
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Word
import GHC.Exts (toList)
import Ouroboros.Consensus.Block (GenesisWindow (..))
import Ouroboros.Consensus.Cardano.Block (CardanoEras, StandardCrypto)
import Ouroboros.Consensus.HardFork.History qualified as History
import PlutusTx (ToData, toData)

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
  -> m ValidityReport
validateTxM params tx utxo = do
  slot <- getSlot
  let mockState = buildMockState params slot utxo
  pure $ case applyTransaction params mockState tx of
    Left err -> ValidityReport False [show err]
    Right _ -> ValidityReport True []

{- | Re-balance fees and re-sign a modified transaction.

After applying TxModifier operations, the transaction body changes which:
1. Invalidates the original signatures (body hash changed)
2. May require different fees (outputs changed)

This function:
1. Calculates the new required fee
2. Adjusts the change output (last output to wallet address) to compensate
3. Re-signs the transaction with the wallet's key

Note: This works at the ledger level to preserve the transaction structure
created by TxModifier operations.
-}
rebalanceAndSign
  :: (MonadMockchain Era m, MonadFail m)
  => Wallet
  -> Tx Era
  -> UTxO Era
  -> m (Tx Era)
rebalanceAndSign wallet tx utxo = do
  pparams <- Convex.Class.queryProtocolParameters
  networkId <- Convex.Class.queryNetworkId
  let walletAddr = Wallet.addressInEra networkId wallet

  -- Get the current fee from the transaction (from the ledger body)
  let currentFee = getTxFeeCoin tx

  -- Create a temp tx with max fee to calculate the actual required fee
  let maxFee = Coin (2 ^ (32 :: Integer) - 1)
      tempTx = setTxFeeCoin maxFee tx
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
  let currentOuts = txOutputs tx
  adjustedOutputs <- adjustChangeOutput walletAddr feeDiff currentOuts

  -- Apply the changes: new fee and adjusted outputs
  let finalTx = setTxOutputsList adjustedOutputs $ setTxFeeCoin newFee tx

  -- Re-sign (strip old signatures and add new one)
  let Tx finalBody _ = finalTx
      unsignedTx = makeSignedTransaction [] finalBody
  pure $ Wallet.signTx wallet unsignedTx

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
adjustChangeOutput
  :: (MonadFail m)
  => AddressInEra Era
  -- ^ Wallet address to find change output
  -> Coin
  -- ^ Fee difference (positive = fee increased)
  -> [TxOut CtxTx Era]
  -- ^ Transaction outputs
  -> m [TxOut CtxTx Era]
adjustChangeOutput walletAddr (Coin feeDiff) outputs = do
  -- Find last output to wallet address
  let indexed = zip [0 ..] outputs
      walletOutputs =
        [ (i, o)
        | (i, o@(TxOut addr _ _ _)) <- indexed
        , addr == walletAddr
        ]
  case listToMaybe (reverse walletOutputs) of
    Nothing -> fail "No change output found to wallet address"
    Just (idx, TxOut addr val datum refScript) -> do
      let Coin oldAda = txOutValueToLovelace val
          newAda = oldAda - feeDiff -- subtract fee increase (or add fee decrease)
      when (newAda < 0) $
        fail "Change output cannot cover fee increase"
      let newLovelace = Coin newAda
          -- Preserve non-Ada assets in the value
          oldValue = txOutValueToValue val
          newValue = oldValue <> negateValue (lovelaceToValue (Coin oldAda)) <> lovelaceToValue newLovelace
          newVal = TxOutValueShelleyBased shelleyBasedEra (toMaryValue newValue)
          newOutput = TxOut addr newVal datum refScript
      pure $ replaceAt idx newOutput outputs

-- | Replace element at index in a list
replaceAt :: Int -> a -> [a] -> [a]
replaceAt _ _ [] = []
replaceAt 0 x (_ : xs) = x : xs
replaceAt n x (y : ys) = y : replaceAt (n - 1) x ys
