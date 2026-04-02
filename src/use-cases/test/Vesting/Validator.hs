{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Vesting.Validator where

import PlutusLedgerApi.V1.Interval (contains)
import PlutusLedgerApi.V1.Value (geq)
import PlutusLedgerApi.V3 (
  Address,
  POSIXTime,
  POSIXTimeRange,
  PubKeyHash,
  TxInInfo (txInInfoOutRef, txInInfoResolved),
  TxInfo (txInfoInputs, txInfoOutputs),
  TxOut (txOutAddress, txOutValue),
  TxOutRef,
  Value,
  from,
 )
import PlutusLedgerApi.V3.Contexts (ScriptContext (..), ScriptInfo (..), txInfoValidRange, txSignedBy)
import PlutusTx (makeLift)
import PlutusTx.Builtins.Internal (unitval)
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.List (foldr)
import PlutusTx.Prelude (BuiltinData, BuiltinUnit, not, otherwise, traceError, zero, (+), (-), (==))

data Vesting = Vesting
  { vDate :: POSIXTime
  , vAmount :: Value
  }

data VestingParams = VestingParams
  { vpOwner :: PubKeyHash
  , vpTranche1 :: Vesting
  , vpTranche2 :: Vesting
  }

makeLift ''Vesting
makeLift ''VestingParams

{-# INLINEABLE availableFrom #-}
availableFrom :: Vesting -> POSIXTimeRange -> Value
availableFrom (Vesting d v) range =
  let validRange = from d
   in if contains validRange range then v else zero

{-# INLINEABLE remainingFrom #-}
remainingFrom :: Vesting -> POSIXTimeRange -> Value
remainingFrom t@Vesting{vAmount = v} vr = v - availableFrom t vr

{-# INLINEABLE mkValidator #-}
mkValidator :: VestingParams -> BuiltinData -> BuiltinUnit
mkValidator
  params
  ( unsafeFromBuiltinData ->
      ctx@ScriptContext
        { scriptContextTxInfo = txI
        }
    )
    | not (txSignedBy txI owner) = traceError "OSM" -- Owner's signature missing
    | not (remainingActual `geq` remainingExpected) = traceError "IRV" -- Insufficient remaining value
    | otherwise = unitval
   where
    owner :: PubKeyHash
    owner = vpOwner params

    validRange :: POSIXTimeRange
    validRange = txInfoValidRange txI

    remainingActual :: Value
    remainingActual =
      let ownAddr = ownScriptAddress ctx txI
       in valueLockedByAddress txI ownAddr

    remainingExpected :: Value
    remainingExpected =
      remainingFrom (vpTranche1 params) validRange
        + remainingFrom (vpTranche2 params) validRange

{-# INLINEABLE validator #-}
validator :: VestingParams -> BuiltinData -> BuiltinUnit
validator = mkValidator

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

{-# INLINEABLE ownInputRef #-}
ownInputRef :: ScriptContext -> TxOutRef
ownInputRef ctx = case scriptContextScriptInfo ctx of
  SpendingScript ref _ -> ref
  _ -> traceError "NSS" -- not a spending script

{-# INLINEABLE ownScriptAddress #-}
ownScriptAddress :: ScriptContext -> TxInfo -> Address
ownScriptAddress ctx txI =
  let _ref = ownInputRef ctx
      inputs = txInfoInputs txI
   in go inputs
 where
  ref = ownInputRef ctx
  go [] = traceError "INF" -- input not found
  go (i : is)
    | txInInfoOutRef i == ref = txOutAddress (txInInfoResolved i)
    | otherwise = go is

{-# INLINEABLE valueLockedByAddress #-}
valueLockedByAddress :: TxInfo -> Address -> Value
valueLockedByAddress txI addr =
  foldr
    (\o acc -> if txOutAddress o == addr then txOutValue o + acc else acc)
    zero
    (txInfoOutputs txI)
