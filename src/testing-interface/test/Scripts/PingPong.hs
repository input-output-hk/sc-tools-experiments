{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Secure PingPong validator.

This validator properly validates:
1. Datum state transitions (Pinged -> Ponged, etc.)
2. Output address - continuation output MUST go to the same script address
3. Output value - continuation output value MUST equal input value

== Security Measures ==

This validator is SECURE against:

1. __Unprotected Script Output Attack__: The 'findContinuationOutput' function
   ensures continuation outputs go to the SAME script address, preventing attackers
   from redirecting funds while satisfying datum requirements.

2. __Large Data Attack__: Uses strict manual 'UnsafeFromData' instances that
   reject datums with extra fields. TH-generated instances (via 'unstableMakeIsData')
   ignore extra fields, allowing attackers to pad datums with arbitrary data.

3. __Large Value Attack__: Validates that output Value equals input Value,
   preventing attackers from adding junk tokens to script outputs. Without this
   check, attackers could mint worthless tokens and attach them to the UTxO,
   increasing min-UTxO requirements and potentially locking funds permanently
   if the bloated Value exceeds transaction size limits.

See 'Scripts.PingPong.Vulnerable' for the vulnerable version.
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
import PlutusLedgerApi.V2.Tx (OutputDatum (NoOutputDatum, OutputDatum, OutputDatumHash), TxOut (TxOut, txOutAddress, txOutDatum, txOutValue))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  ScriptInfo (SpendingScript),
  TxInInfo (TxInInfo, txInInfoOutRef, txInInfoResolved),
  TxInfo (..),
 )
import PlutusLedgerApi.V3.Tx (TxOutRef)
import PlutusTx (unstableMakeIsData)
import PlutusTx.AssocMap (Map, lookup)
import PlutusTx.Builtins (mkConstr, unsafeDataAsConstr)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (ToData (..), UnsafeFromData (..))
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

{- | Strict ToData/UnsafeFromData instances for PingPongState.

== Large Data Attack Mitigation ==

These instances are written manually instead of using 'unstableMakeIsData' because
TH-generated instances silently ignore extra fields in the datum:

1. Attacker creates datum: @Constr 0 [junk1, junk2, ...]@
2. TH-generated FromData parses this as valid (Pinged), ignoring extra fields
3. The bloated UTxO may become __permanently unspendable__:

   - Deserialization exceeds execution unit limits
   - Transaction to spend it exceeds protocol size limits
   - Funds are locked forever with no recovery possible

Our strict instances check that the field list is EMPTY for nullary constructors,
rejecting any datum with unexpected extra fields before it reaches the chain.
-}

-- | Strict ToData instance for PingPongState
instance ToData PingPongState where
  {-# INLINEABLE toBuiltinData #-}
  toBuiltinData Pinged = mkConstr 0 []
  toBuiltinData Ponged = mkConstr 1 []
  toBuiltinData Stopped = mkConstr 2 []

-- | Strict UnsafeFromData instance - errors on datums with extra fields
instance UnsafeFromData PingPongState where
  {-# INLINEABLE unsafeFromBuiltinData #-}
  unsafeFromBuiltinData d =
    let (idx, fields) = unsafeDataAsConstr d
     in if isEmptyList fields
          then
            if idx P.== 0
              then Pinged
              else
                if idx P.== 1
                  then Ponged
                  else
                    if idx P.== 2
                      then Stopped
                      else P.traceError "PingPongState: invalid index"
          else P.traceError "PingPongState: unexpected extra fields"
   where
    isEmptyList :: [a] -> P.Bool
    isEmptyList [] = P.True
    isEmptyList _ = P.False

PlutusTx.unstableMakeIsData ''PingPongRedeemer

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

      -- SECURITY: Verify output value equals input value (prevent Large Value Attack)
      -- An attacker could add junk tokens which increases min-UTxO and may lock funds
      inputValue = txOutValue (txInInfoResolved ownInput)
      outputValue = txOutValue continuationOutput

      -- Get next state from the continuation output at our address
      nextState = getStateFromTxOut datumMap "output" continuationOutput
     in
      if inputValue P./= outputValue
        then P.traceError "Value mismatch: output value must equal input value"
        else case (currentState, action, nextState) of
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
