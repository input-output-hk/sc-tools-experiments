{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Vulnerable PingPong validator for threat model demonstration.

This validator is INTENTIONALLY VULNERABLE to the "Unprotected Script Output"
attack pattern. It validates datum state transitions but does NOT check that
outputs go to the correct script address.

VULNERABILITY: An attacker can redirect the continuation output to their own
address while satisfying the datum requirements, effectively stealing funds.

Use this module to demonstrate how the UnprotectedScriptOutput threat model
detects this vulnerability class.

See 'Scripts.PingPong' for the secure version.
-}
module Scripts.PingPong.Vulnerable.UnprotectedScriptOutput (
  validator,
  -- Re-export types from secure version for compatibility
  PingPongState (..),
  PingPongRedeemer (..),
) where

import PlutusLedgerApi.V1.Scripts (Datum (getDatum), DatumHash, Redeemer (..))

import PlutusLedgerApi.V2.Tx (OutputDatum (NoOutputDatum, OutputDatum, OutputDatumHash), TxOut (..))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  TxInInfo (TxInInfo, txInInfoResolved),
  TxInfo (..),
 )
import PlutusTx.AssocMap (Map, lookup)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P

-- Re-use types and helpers from the secure version
import Scripts.PingPong (PingPongRedeemer (..), PingPongState (..), showAction, showState)

{- | VULNERABLE VALIDATOR

This validator only checks datum state transitions but does NOT verify
that outputs go to the same script address.

An attacker can:
1. Spend a script UTxO
2. Create an output with valid next-state datum to ANY address
3. The validator passes because it only checks the datum, not the address

The attacker effectively steals the funds by redirecting them to their wallet.
-}
{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> action :: PingPongRedeemer)
        , scriptContextTxInfo =
          txInfo@TxInfo
            { txInfoInputs = (getStateFromInputs (txInfoData txInfo) -> currentState)
            , -- VULNERABILITY: Takes first output regardless of address!
            txInfoOutputs = (getStateFromOutputs (txInfoData txInfo) -> nextState)
            }
        }
    ) = case (currentState, action, nextState) of
    (Pinged, Pong, Ponged) ->
      BI.unitval
    (Ponged, Ping, Pinged) ->
      BI.unitval
    (Pinged, Stop, Stopped) ->
      BI.unitval
    (Ponged, Stop, Stopped) ->
      BI.unitval
    _ ->
      P.traceError P.$ "Coverage: BRANCH_INVALID state=" `P.appendString` showState currentState `P.appendString` " action=" `P.appendString` showAction action `P.appendString` " nextState=" `P.appendString` showState nextState

{-# INLINEABLE getStateFromInputs #-}
getStateFromInputs :: Map DatumHash Datum -> [TxInInfo] -> PingPongState
getStateFromInputs _ [] = P.traceError "No inputs"
getStateFromInputs txInfoData' (TxInInfo{txInInfoResolved = TxOut{txOutDatum}} : _) = getPingPongState txInfoData' "Datum on input" txOutDatum

-- VULNERABILITY: This function takes the FIRST output without checking its address
{-# INLINEABLE getStateFromOutputs #-}
getStateFromOutputs :: Map DatumHash Datum -> [TxOut] -> PingPongState
getStateFromOutputs _ [] = P.traceError "No outputs"
getStateFromOutputs txInfoDatum' (TxOut{txOutDatum} : _) = getPingPongState txInfoDatum' "Datum on output " txOutDatum

{-# INLINEABLE getPingPongState #-}
getPingPongState :: Map DatumHash Datum -> P.BuiltinString -> OutputDatum -> PingPongState
getPingPongState _ _ (OutputDatum (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState)) = state
getPingPongState _ errorMsg NoOutputDatum = P.traceError P.$ P.appendString errorMsg " - NoOutputDatum"
getPingPongState datumMap errorMsg (OutputDatumHash hash) = case lookup hash datumMap of
  P.Just (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState) -> state
  P.Nothing -> P.traceError P.$ P.appendString errorMsg " - OutputDatumHash not found in datum map"
