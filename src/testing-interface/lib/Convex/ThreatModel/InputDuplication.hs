{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

{- | Threat model for detecting input ordering bypass vulnerabilities.

Some Plutus validators have logic like:
@
  or {
    own_ref != first_script_input_ref,  -- If NOT first → skip check!
    actual_validation_logic(...)        -- Only verified for first input
  }
@

This pattern is vulnerable because when multiple script inputs are spent
in one transaction, only the FIRST input is properly validated. An attacker
can add a second input from the same script which bypasses all validation.

This is particularly dangerous for:
- Lending protocols (second loan bypasses payment verification)
- Multi-signature schemes (second input bypasses signature checks)
- Any validator that assumes it's the only script input
-}
module Convex.ThreatModel.InputDuplication (
  inputDuplication,
) where

import Cardano.Api qualified as C
import Cardano.Ledger.Alonzo.Scripts qualified as Ledger
import Cardano.Ledger.Plutus.Language qualified as Plutus
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)

import Convex.ThreatModel
import Convex.ThreatModel.Cardano.Api (Era, IsPlutusScriptInEra)

-- | A Plutus script that can be either V2 or V3
data SomePlutusScript where
  SomePlutusScript :: (IsPlutusScriptInEra lang) => C.PlutusScript lang -> SomePlutusScript

{- | Check for input duplication / input ordering bypass vulnerabilities.

For a transaction that spends from a script address:

1. Find a script input in the transaction
2. Look in the UTxO set for OTHER UTxOs at the same script address that aren't already spent
3. Add one of those as an additional input with the same redeemer
4. If the transaction still validates, the script has an input ordering vulnerability

The attack works because many scripts only validate the FIRST script input,
allowing subsequent inputs to bypass validation entirely.

Note: This threat model requires that there exist multiple UTxOs at the same
script address in the UTxO set. The test will be skipped if no additional
UTxOs are available.
-}
inputDuplication :: ThreatModel ()
inputDuplication = Named "Input Duplication" $ do
  -- Get the environment to access the full UTxO set and the original transaction
  ThreatModelEnv tx (C.UTxO utxoMap) _ <- getThreatModelEnv

  -- Find a script input (non-key address = script address)
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)
  let scriptAddr = addressOf scriptInput
      existingTxIn = inputTxIn scriptInput

  -- Get the redeemer for this input (we'll use the same for the new input)
  redeemer <-
    getRedeemer scriptInput >>= \case
      Nothing -> failPrecondition "Script input missing redeemer"
      Just redeemer' -> pure redeemer'

  -- Find OTHER UTxOs at the same script address that aren't already inputs
  txInputsList <- getTxInputs
  let existingInputTxIns = map inputTxIn txInputsList

  let otherScriptUtxos =
        [ (txIn, txOut)
        | (txIn, txOut) <- Map.toList utxoMap
        , addressOfTxOut' txOut == scriptAddr
        , txIn /= existingTxIn
        , txIn `notElem` existingInputTxIns
        ]

  -- Precondition: there must be another UTxO at the same script address
  threatPrecondition $ ensure (not $ null otherScriptUtxos)

  -- Pick one of the other UTxOs to add as an additional input
  (newTxIn, newTxOut) <- pickAny otherScriptUtxos

  counterexampleTM $
    paragraph
      [ "The transaction spends a script UTxO at"
      , show $ prettyAddress scriptAddr
      ]

  counterexampleTM $
    paragraph
      [ "Found another UTxO at the same script address:"
      , show newTxIn
      , "Testing if adding this as an additional input bypasses validation."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script has an INPUT ORDERING BYPASS vulnerability."
      , "The validator only checks the first script input, allowing subsequent"
      , "inputs to bypass all validation logic (e.g., payment verification)."
      ]

  -- Get the datum from the new UTxO
  let newValue = valueOfTxOut' newTxOut
      newDatum = extractDatum newTxOut

  -- Extract the script hash from the address
  let scriptHash = extractScriptHash scriptAddr

  -- Extract the actual script from the transaction's witness set
  -- This is needed to properly add the script to the new input's witness
  let scripts = extractTxScripts tx

  -- Get attacker address (one of the transaction signers) to receive stolen value
  signer <- anySigner
  let attackerAddr = keyAddressAny signer
      -- Add output to attacker's address to conserve value (real attack scenario)
      attackerOutput = addOutput attackerAddr newValue C.TxOutDatumNone C.ReferenceScriptNone

  -- Try to find a Plutus script (V2 or V3) with the matching hash
  case findPlutusScriptByHash scriptHash scripts of
    Just (SomePlutusScript plutusScript) -> do
      -- Add the new script input with the V2 script, plus attacker output
      shouldNotValidate $
        addPlutusScriptInput plutusScript newValue newDatum redeemer C.ReferenceScriptNone
          <> attackerOutput
    Nothing ->
      -- Script not found in witness set - this shouldn't happen for a valid tx
      -- but if it does, we skip this test as a precondition failure
      failPrecondition "Script not found in transaction witness set"
 where
  -- Helper to get address from TxOut CtxUTxO
  addressOfTxOut' :: C.TxOut C.CtxUTxO C.ConwayEra -> AddressAny
  addressOfTxOut' (C.TxOut (C.AddressInEra C.ShelleyAddressInEra{} addr) _ _ _) = C.AddressShelley addr
  addressOfTxOut' (C.TxOut (C.AddressInEra C.ByronAddressInAnyEra{} addr) _ _ _) = C.AddressByron addr

  -- Helper to get value from TxOut CtxUTxO
  valueOfTxOut' :: C.TxOut C.CtxUTxO C.ConwayEra -> C.Value
  valueOfTxOut' (C.TxOut _ val _ _) = C.txOutValueToValue val

  -- Extract datum from TxOut, converting to TxOutDatum CtxTx
  extractDatum :: C.TxOut C.CtxUTxO C.ConwayEra -> Datum
  extractDatum txOut = case datumOfTxOut txOut of
    C.TxOutDatumNone -> C.TxOutDatumNone
    C.TxOutDatumHash era h -> C.TxOutDatumHash era h
    C.TxOutDatumInline _era sd ->
      -- Convert inline datum to supplemental datum format for the new input
      -- Use AlonzoEraOnwardsConway for the SupplementalDatum era witness
      C.TxOutSupplementalDatum C.AlonzoEraOnwardsConway sd

  -- Extract script hash from a script address
  extractScriptHash :: AddressAny -> C.ScriptHash
  extractScriptHash (C.AddressShelley addr) =
    case C.shelleyPayAddrToPlutusPubKHash addr of
      Nothing ->
        -- It's a script address, extract the hash
        case addr of
          C.ShelleyAddress _ cred _ ->
            case C.fromShelleyPaymentCredential cred of
              C.PaymentCredentialByScript h -> h
              C.PaymentCredentialByKey _ -> error "Expected script address"
      Just _ -> error "Expected script address, got key address"
  extractScriptHash _ = error "Expected Shelley address"

  -- Extract the list of scripts from a transaction's witness set
  extractTxScripts :: C.Tx Era -> [Ledger.AlonzoScript (C.ShelleyLedgerEra Era)]
  extractTxScripts (C.Tx (C.ShelleyTxBody _ _ scripts _ _ _) _) = scripts

  -- Find a Plutus script (V2 or V3) by its hash in the list of ledger scripts
  findPlutusScriptByHash
    :: C.ScriptHash
    -> [Ledger.AlonzoScript (C.ShelleyLedgerEra Era)]
    -> Maybe SomePlutusScript
  findPlutusScriptByHash targetHash scripts =
    case mapMaybe (tryConvertScript targetHash) scripts of
      (s : _) -> Just s
      [] -> Nothing

  -- Try to convert a ledger script to a SomePlutusScript if the hash matches
  tryConvertScript
    :: C.ScriptHash
    -> Ledger.AlonzoScript (C.ShelleyLedgerEra Era)
    -> Maybe SomePlutusScript
  tryConvertScript targetHash (Ledger.PlutusScript ps) =
    -- Use withPlutusScript to get the language at runtime
    Ledger.withPlutusScript ps $ \(plutus :: Plutus.Plutus l) ->
      let binaryBytes = Plutus.unPlutusBinary (Plutus.plutusBinary plutus)
          serialised :: C.PlutusScript (C.FromLedgerPlutusLanguage l)
          serialised = C.PlutusScriptSerialised binaryBytes
          asScript
            :: (lang ~ C.FromLedgerPlutusLanguage l, IsPlutusScriptInEra lang)
            => C.PlutusScriptVersion lang -> Maybe SomePlutusScript
          asScript ver =
            if C.hashScript (C.PlutusScript ver serialised) == targetHash
              then Just (SomePlutusScript serialised)
              else Nothing
       in case Plutus.isLanguage @l of
            Plutus.SPlutusV1 -> asScript C.PlutusScriptV1
            Plutus.SPlutusV2 -> asScript C.PlutusScriptV2
            Plutus.SPlutusV3 -> asScript C.PlutusScriptV3
            -- PlutusV4 is only available in Dijkstra
            Plutus.SPlutusV4 -> Nothing
  tryConvertScript _ (Ledger.NativeScript _) = Nothing
