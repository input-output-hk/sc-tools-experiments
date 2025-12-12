{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}

-- A plutus validator that only succeeds if the redeemer is identical to the script's input index
module Scripts.PingPong (
  validator,
  validatorSimplified,
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
import PlutusTx (Data (..), unstableMakeIsData)
import PlutusTx.AssocMap (Map, lookup, toList)
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

-- deriving anyclass (ToJSON, FromJSON)

data PingPongRedeemer = Ping | Pong | Stop
  deriving stock (Haskell.Show)

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

-- deriving anyclass (ToJSON, FromJSON)

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
    (Pinged, Pong, Ponged) -> BI.unitval
    (Ponged, Ping, Pinged) -> BI.unitval
    (Pinged, Stop, Stopped) -> BI.unitval
    (Ponged, Stop, Stopped) -> BI.unitval
    _ -> P.traceError P.$ "Invalid state transition: " `P.appendString` showState currentState `P.appendString` showAction action `P.appendString` showState nextState

{-# INLINEABLE validatorSimplified #-}
validatorSimplified :: BuiltinData -> BuiltinUnit
validatorSimplified
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> action :: PingPongRedeemer)
        , scriptContextTxInfo =
          txInfo@TxInfo
            { -- txInfoInputs = (getStateFromInputs -> currentState)
            txInfoOutputs = (getStateFromOutpusts (txInfoData txInfo) -> nextState)
            }
        }
    ) = case (action, nextState) of
    (Pong, Ponged) -> BI.unitval
    (Ping, Pinged) -> BI.unitval
    (Stop, Stopped) -> BI.unitval
    _ -> P.traceError "Invalid state transition"

{-# INLINEABLE getStateFromInputs #-}
getStateFromInputs :: Map DatumHash Datum -> [TxInInfo] -> PingPongState
getStateFromInputs _ [] = P.traceError "No inputs"
getStateFromInputs txInfoData' (TxInInfo{txInInfoResolved = TxOut{txOutDatum}} : _) = getPingPongState txInfoData' "Datum on input" txOutDatum

-- getStateFromInputs _ _ = P.traceError "Multiple inputs"

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

-- getPingPongState errorMsg (OutputDatum datum) =
--   -- let d = getDatum datum
--   P.traceError P.$ errorMsg

{-# INLINEABLE inspectDatum #-}
inspectDatum :: BuiltinData -> P.BuiltinString
inspectDatum d =
  case BI.builtinDataToData d of
    Constr i _ -> "Constructor " -- `P.appendString` showInt i
    Map _ -> "Map"
    List _ -> "List"
    I _ -> "Integer"
    B _ -> "ByteString"
