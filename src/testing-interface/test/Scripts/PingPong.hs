{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Secure PingPong validator.

This validator properly validates:
1. Datum state transitions (Pinged -> Ponged, etc.)
2. Output address - continuation output MUST go to the same script address

This prevents the "Unprotected Script Output" vulnerability where an attacker
could redirect funds while satisfying datum requirements.

See 'Scripts.PingPong.Vulnerable.UnprotectedScriptOutput' for the vulnerable version
used to demonstrate the threat model.
-}
module Scripts.PingPong (
  validator,
  PingPongState (..),
  PingPongRedeemer (..),
  -- Helpers for error messages (used by vulnerable version too)
  showState,
  showAction,
) where

import PlutusLedgerApi.V1.Address (Address (..))
import PlutusLedgerApi.V1.Scripts (Datum (getDatum), DatumHash, Redeemer (..))
import PlutusLedgerApi.V2.Tx (OutputDatum (NoOutputDatum, OutputDatum, OutputDatumHash), TxOut (..))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  ScriptInfo (SpendingScript),
  TxInInfo (TxInInfo, txInInfoOutRef, txInInfoResolved),
  TxInfo (..),
 )
import PlutusLedgerApi.V3.Tx (TxOutRef)
import PlutusTx (unstableMakeIsData)
import PlutusTx.AssocMap (Map, lookup)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P
import PlutusTx.Show qualified as P
import Prelude qualified as Haskell

data PingPongState = Pinged | Ponged | Stopped
  deriving stock (Haskell.Eq, Haskell.Show)

{-# INLINEABLE showState #-}
showState :: PingPongState -> P.BuiltinString
showState Pinged = "Pinged "
showState Ponged = "Ponged "
showState Stopped = "Stopped "

data PingPongRedeemer = Ping | Pong | Stop
  deriving stock (Haskell.Eq, Haskell.Show)

{-# INLINEABLE showAction #-}
showAction :: PingPongRedeemer -> P.BuiltinString
showAction Ping = "Ping "
showAction Pong = "Pong "
showAction Stop = "Stop "

instance P.Show PingPongRedeemer where
  {-# INLINEABLE show #-}
  show = showAction

instance P.Show PingPongState where
  {-# INLINEABLE show #-}
  show = showState

PlutusTx.unstableMakeIsData ''PingPongRedeemer
PlutusTx.unstableMakeIsData ''PingPongState

{- | SECURE VALIDATOR

This validator checks both:
1. Datum state transitions (same as vulnerable version)
2. Output address - continuation MUST go to the SAME script address

The key security check is in 'findContinuationOutput' which ensures the
output we validate is actually at our own script address.
-}
{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextScriptInfo = SpendingScript ownTxOutRef _
        , scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> action :: PingPongRedeemer)
        , scriptContextTxInfo =
          TxInfo
            { txInfoInputs
            , txInfoOutputs
            , txInfoData = datumMap
            }
        }
    ) =
    let
      -- Find our own input to get our address
      ownInput = findOwnInput ownTxOutRef txInfoInputs
      ownAddress = txOutAddress (txInInfoResolved ownInput)

      -- Get current state from our input
      currentState = getStateFromTxOut datumMap "input" (txInInfoResolved ownInput)

      -- SECURITY: Find continuation output AT OUR OWN ADDRESS
      -- This is the key fix - we don't just take any output with valid datum
      continuationOutput = findContinuationOutput ownAddress txInfoOutputs

      -- Get next state from the continuation output at our address
      nextState = getStateFromTxOut datumMap "output" continuationOutput
     in
      case (currentState, action, nextState) of
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
validator _ = P.traceError "Invalid script purpose - expected SpendingScript"

-- | Find our own input by matching the TxOutRef from SpendingScript
{-# INLINEABLE findOwnInput #-}
findOwnInput :: TxOutRef -> [TxInInfo] -> TxInInfo
findOwnInput _ [] = P.traceError "Own input not found"
findOwnInput ref (inp@TxInInfo{txInInfoOutRef} : rest)
  | txInInfoOutRef P.== ref = inp
  | P.otherwise = findOwnInput ref rest

{- | SECURITY CRITICAL: Find output at our own address.

This is the key security fix. Instead of taking any output with a valid
PingPong datum, we find the output that goes to OUR script address.

This prevents an attacker from:
1. Creating an output with valid datum to THEIR address
2. Stealing the funds while satisfying the datum check
-}
{-# INLINEABLE findContinuationOutput #-}
findContinuationOutput :: Address -> [TxOut] -> TxOut
findContinuationOutput _ [] = P.traceError "No continuation output at script address"
findContinuationOutput ownAddr (out@TxOut{txOutAddress} : rest)
  | txOutAddress P.== ownAddr = out
  | P.otherwise = findContinuationOutput ownAddr rest

-- | Get PingPong state from a TxOut's datum
{-# INLINEABLE getStateFromTxOut #-}
getStateFromTxOut :: Map DatumHash Datum -> P.BuiltinString -> TxOut -> PingPongState
getStateFromTxOut datumMap errorCtx TxOut{txOutDatum} =
  getPingPongState datumMap errorCtx txOutDatum

{-# INLINEABLE getPingPongState #-}
getPingPongState :: Map DatumHash Datum -> P.BuiltinString -> OutputDatum -> PingPongState
getPingPongState _ _ (OutputDatum (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState)) = state
getPingPongState _ errorMsg NoOutputDatum = P.traceError P.$ P.appendString errorMsg " - NoOutputDatum"
getPingPongState datumMap errorMsg (OutputDatumHash hash) = case lookup hash datumMap of
  P.Just (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState) -> state
  P.Nothing -> P.traceError P.$ P.appendString errorMsg " - OutputDatumHash not found in datum map"
