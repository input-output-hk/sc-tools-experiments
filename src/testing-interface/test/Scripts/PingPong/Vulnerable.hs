{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Vulnerable PingPong validator for threat model demonstration.

This validator is INTENTIONALLY VULNERABLE to demonstrate multiple attack patterns:

1. __Unprotected Script Output Attack__: The validator checks datum state transitions
   but does NOT verify that outputs go to the correct script address. An attacker
   can redirect the continuation output to their own address while satisfying
   the datum requirements, effectively stealing funds.

2. __Large Data Attack__: Uses 'unstableMakeIsData' which generates parsers
   that ignore extra fields in Constr data. An attacker can create datums with
   arbitrary extra data that the validator accepts. This can:

   - Increase execution costs for anyone spending the UTxO
   - __Permanently lock funds__ if the bloated datum causes the UTxO to exceed
     execution limits or transaction size constraints, making it unspendable

3. __Large Value Attack__: The validator does NOT verify that the output Value
   equals the input Value. An attacker can mint junk tokens and add them to the
   script output. This can:

   - Increase min-UTxO requirements (more ADA locked up)
   - Add serialization/deserialization costs
   - __Permanently lock funds__ if the bloated Value causes the UTxO to exceed
     transaction size limits, making it unspendable
   - Force legitimate users to handle/dispose of unwanted tokens

Use this module to demonstrate how threat models detect these vulnerability classes.

See 'Scripts.PingPong' for the secure version.
-}
module Scripts.PingPong.Vulnerable (
  validator,
  -- Local vulnerable types with permissive parsing
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
import PlutusTx (unstableMakeIsData)
import PlutusTx.AssocMap (Map, lookup)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P
import Prelude qualified as Haskell

-- | The state of the ping pong contract
data PingPongState = Pinged | Ponged | Stopped
  deriving stock (Haskell.Eq, Haskell.Show)

-- | Redeemer for the ping pong contract
data PingPongRedeemer = Ping | Pong | Stop
  deriving stock (Haskell.Eq, Haskell.Show)

-- | Show a state in Plutus
{-# INLINEABLE showState #-}
showState :: PingPongState -> P.BuiltinString
showState Pinged = "Pinged"
showState Ponged = "Ponged"
showState Stopped = "Stopped"

-- | Show an action in Plutus
{-# INLINEABLE showAction #-}
showAction :: PingPongRedeemer -> P.BuiltinString
showAction Ping = "Ping"
showAction Pong = "Pong"
showAction Stop = "Stop"

-- VULNERABLE: Using unstableMakeIsData generates permissive parsers
-- that ignore extra fields in Constr data, making this vulnerable
-- to Large Data Attacks
PlutusTx.unstableMakeIsData ''PingPongRedeemer
PlutusTx.unstableMakeIsData ''PingPongState

{- | VULNERABLE VALIDATOR

This validator only checks datum state transitions but does NOT verify:
- That outputs go to the same script address (Unprotected Output Attack)
- That output Value equals input Value (Large Value Attack)

An attacker can:
1. Spend a script UTxO
2. Create an output with valid next-state datum to ANY address
3. The validator passes because it only checks the datum, not the address

The attacker effectively steals the funds by redirecting them to their wallet.

For Large Value Attack, an attacker can mint junk tokens and add them to the
script output, potentially bloating it to the point of being unspendable.
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
