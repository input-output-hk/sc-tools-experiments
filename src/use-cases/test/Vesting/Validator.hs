{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Vesting.Validator where

import GHC.Real (Integral (toInteger))
import PlutusLedgerApi.V1.Interval (contains)
import PlutusLedgerApi.V1.Value (geq, lovelaceValueOf)
import PlutusLedgerApi.V3 (Address, Extended (..), Interval (..), LowerBound (..), POSIXTime, POSIXTimeRange, PubKeyHash, TxInInfo (txInInfoOutRef, txInInfoResolved), TxInfo (txInfoInputs, txInfoOutputs), TxOut (txOutAddress, txOutValue), TxOutRef, UpperBound (..), Value, from, getDatum)
import PlutusLedgerApi.V3.Contexts (ScriptContext (..), ScriptInfo (..), txInfoValidRange, txSignedBy)
import PlutusTx (makeLift)
import PlutusTx.Builtins.Internal (unitval)
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.List (find)
import PlutusTx.Prelude (BuiltinData, BuiltinString, BuiltinUnit, Maybe (..), mconcat, not, otherwise, traceError, zero, ($), (+), (-), (<>), (==))
import PlutusTx.Show (Show (..))

data Vesting = Vesting
  { vDate :: POSIXTime
  , vAmount :: Value
  }

data VestingParams = VestingParams
  { vpOwner :: PubKeyHash
  , vpTranche1 :: Vesting
  , vpTranche2 :: Vesting
  }

-- unstableMakeIsData ''Vesting
makeLift ''Vesting

-- unstableMakeIsData ''VestingParams
makeLift ''VestingParams

{-# INLINEABLE availableFrom #-}

-- | The amount guaranteed to be available from a given tranche in a given time range.
availableFrom :: Vesting -> POSIXTimeRange -> Value
availableFrom (Vesting d v) range =
  -- The valid range is an open-ended range starting from the tranche vesting date
  let validRange = from d
   in -- If the valid range completely contains the argument range (meaning in particular
      -- that the start time of the argument range is after the tranche vesting date), then
      -- the money in the tranche is available, otherwise nothing is available.
      if contains validRange range then v else zero

{-# INLINEABLE remainingFrom #-}

-- | The amount that has not been released from this tranche yet
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
    | not (remainingActual `geq` remainingExpected) =
        traceError
          ( "insufficient remaining value at this time slot =>"
              <> " actual: "
              <> show (lovelaceValueOf remainingActual)
              <> " expected: "
              <> show (lovelaceValueOf remainingExpected)
              <> " time range: "
              <> showInterval validRange
          )
    | not (txSignedBy txI owner) =
        traceError
          ( "owner's signature missing => "
              <> " actual: "
              <> show (lovelaceValueOf remainingActual)
              <> " expected: "
              <> show (lovelaceValueOf remainingExpected)
          )
    | otherwise = unitval
   where
    owner :: PubKeyHash
    owner = vpOwner params

    vt1 :: Vesting
    vt1 = vpTranche1 params

    vt2 :: Vesting
    vt2 = vpTranche2 params

    validRange :: POSIXTimeRange
    validRange = txInfoValidRange txI

    remainingActual :: Value
    remainingActual = valueLockedByAddress txI (ownScriptAddress ctx)

    remainingExpected :: Value
    remainingExpected = remainingFrom vt1 validRange + remainingFrom vt2 validRange

{-# INLINEABLE validator #-}
validator :: VestingParams -> BuiltinData -> BuiltinUnit
validator = mkValidator

-------------------------------------------------------------------------------
-- @TODO: Replace the functions below with UTXO indexers
-------------------------------------------------------------------------------

{-# INLINEABLE ownInputRef #-}
ownInputRef :: ScriptContext -> TxOutRef
ownInputRef ctx = case scriptContextScriptInfo ctx of
  SpendingScript ref _ -> ref
  _ -> traceError "ownInputRef: not a spending script"

{-# INLINEABLE ownInput #-}
ownInput :: TxInfo -> TxOutRef -> TxOut
ownInput txI ref =
  let inputs = txInfoInputs txI
      mInput = find (\i -> txInInfoOutRef i == ref) inputs
   in case mInput of
        Just i -> txInInfoResolved i
        Nothing -> traceError "ownInput: input not found"

{-# INLINEABLE ownScriptAddress #-}
ownScriptAddress :: ScriptContext -> Address
ownScriptAddress ctx =
  let
    txI = scriptContextTxInfo ctx
    ref = ownInputRef ctx
    txOut = ownInput txI ref
   in
    txOutAddress txOut

{-# INLINEABLE valueLockedByAddress #-}
valueLockedByAddress :: TxInfo -> Address -> Value
valueLockedByAddress txI addr = mconcat [txOutValue o | o <- txInfoOutputs txI, txOutAddress o == addr]

-------------------------------------------------------------------------------
-- The functions below are used only for debugging purposes
-------------------------------------------------------------------------------

{-# INLINEABLE showPOSIXTime #-}
showPOSIXTime :: POSIXTime -> BuiltinString
showPOSIXTime t = show $ toInteger t

{-# INLINEABLE showInterval #-}
showInterval :: POSIXTimeRange -> BuiltinString
showInterval (Interval l h) = "Interval: " <> showLowerBound l <> " to " <> showUpperBound h

{-# INLINEABLE showLowerBound #-}
showLowerBound :: LowerBound POSIXTime -> BuiltinString
showLowerBound (LowerBound NegInf _) = "negative infinity"
showLowerBound (LowerBound (Finite t) _) = show $ toInteger t
showLowerBound (LowerBound PosInf _) = "positive infinity"

{-# INLINEABLE showUpperBound #-}
showUpperBound :: UpperBound POSIXTime -> BuiltinString
showUpperBound (UpperBound NegInf _) = "negative infinity"
showUpperBound (UpperBound (Finite t) _) = show $ toInteger t
showUpperBound (UpperBound PosInf _) = "positive infinity"
