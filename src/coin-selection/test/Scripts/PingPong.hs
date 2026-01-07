{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

-- A plutus validator that only succeeds if the redeemer is identical to the script's input index
module Scripts.PingPong (
  validator,
  PingPongRedeemer (..),
  PingPongState (..),
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

{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> action :: PingPongRedeemer)
        , scriptContextTxInfo =
          txInfo@TxInfo
            { txInfoInputs = (getStateFromInputs (txInfoData txInfo) -> currentState)
            , txInfoOutputs = (getStateFromOutpusts (txInfoData txInfo) -> nextState)
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

{-# INLINEABLE getStateFromOutpusts #-}
getStateFromOutpusts :: Map DatumHash Datum -> [TxOut] -> PingPongState
getStateFromOutpusts _ [] = P.traceError "No outputs"
getStateFromOutpusts txInfoDatum' (TxOut{txOutDatum} : _) = getPingPongState txInfoDatum' "Datum on output " txOutDatum

{-# INLINEABLE getPingPongState #-}
getPingPongState :: Map DatumHash Datum -> P.BuiltinString -> OutputDatum -> PingPongState
getPingPongState _ _ (OutputDatum (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState)) = state
getPingPongState _ errorMsg NoOutputDatum = P.traceError P.$ P.appendString errorMsg " - NoOutputDatum"
getPingPongState datumMap errorMsg (OutputDatumHash hash) = case lookup hash datumMap of
  P.Just (unsafeFromBuiltinData P.. getDatum -> state :: PingPongState) -> state
  P.Nothing -> P.traceError P.$ P.appendString errorMsg " - OutputDatumHash not found in datum map"
