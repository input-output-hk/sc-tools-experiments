{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-incomplete-patterns #-}

module Escrow.Validator where

import PlutusLedgerApi.V1.Interval (before, contains, to)
import PlutusLedgerApi.V1.Value (geq)
import PlutusLedgerApi.V3 (
  Address,
  Credential (..),
  Datum (..),
  OutputDatum (..),
  POSIXTime,
  POSIXTimeRange,
  PubKeyHash,
  Redeemer (getRedeemer),
  ScriptHash,
  TxInfo (txInfoOutputs),
  TxOut (txOutAddress, txOutDatum, txOutValue),
  Value,
  addressCredential,
 )
import PlutusLedgerApi.V3.Contexts (ScriptContext (..), ScriptInfo (..), txInfoValidRange, txSignedBy)
import PlutusTx (makeIsDataIndexed, makeLift)
import PlutusTx.Builtins (BuiltinData)
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.List (all, foldr)
import PlutusTx.Prelude (Bool (..), BuiltinUnit, Maybe (..), not, otherwise, traceError, zero, (&&), (+), (-), (==))
import PlutusTx.Prelude qualified as PlutusTx

-------------------------------------------------------------------------------
-- Types
-------------------------------------------------------------------------------

{- | A single target the escrow must satisfy when redeemed.
  Either a payment to a public key or a payment to a script with an inline datum.
-}
data EscrowTarget
  = PaymentPubKeyTarget PubKeyHash Value
  | ScriptTarget ScriptHash Datum Value

makeLift ''EscrowTarget

-- | Compile-time parameters baked into the script at compilation.
data EscrowParams = EscrowParams
  { epDeadline :: POSIXTime
  -- ^ Latest point at which a Redeem is valid (exclusive upper bound for Refund).
  , epTargets :: [EscrowTarget]
  -- ^ Outputs that must be produced by a Redeem transaction.
  }

makeLift ''EscrowParams

-- | Redeemer: collect the funds (Redeem) or reclaim a deposit after the deadline (Refund).
data Action = Redeem | Refund

makeIsDataIndexed ''Action [('Redeem, 0), ('Refund, 1)]

-------------------------------------------------------------------------------
-- Validator
-------------------------------------------------------------------------------

{-# INLINEABLE mkValidator #-}

{- | datum   = contributor PubKeyHash (inline, decoded from BuiltinData)
  redeemer = Action (Redeem | Refund)
  context  = ScriptContext
-}
mkValidator :: EscrowParams -> ScriptContext -> Bool
mkValidator params (ScriptContext txI scriptRedeemer scriptInfo) =
  case action of
    Redeem
      | not (to deadline `contains` validRange) -> traceError "DLP" -- Deadline passed
      | not (all (meetsTarget txI) targets) -> traceError "TGT" -- Targets not met
      | otherwise -> True
    Refund
      | not ((deadline - 1) `before` validRange) -> traceError "DNP" -- Deadline not passed yet
      | not (txSignedBy txI contributor) -> traceError "SNS" -- Contributor's signature missing
      | otherwise -> True
 where
  -- Extract redeemer from script context
  action :: Action
  action = case PlutusTx.fromBuiltinData (getRedeemer scriptRedeemer) of
    Nothing -> PlutusTx.traceError "Failed to parse Action redeemer"
    Just r -> r

  contributor :: PubKeyHash
  contributor = case scriptInfo of
    SpendingScript _ (Just (Datum d)) ->
      case PlutusTx.fromBuiltinData d of
        Just pkh -> pkh
        Nothing -> PlutusTx.traceError "Failed to parse contributor PubKeyHash from datum"
    _ -> PlutusTx.traceError "Expected SpendingScript with inline datum"

  deadline :: POSIXTime
  deadline = epDeadline params

  targets :: [EscrowTarget]
  targets = epTargets params

  validRange :: POSIXTimeRange
  validRange = txInfoValidRange txI

{-# INLINEABLE validator #-}
validator :: EscrowParams -> BuiltinData -> BuiltinUnit
validator params ctx =
  PlutusTx.check
    ( mkValidator
        params
        (unsafeFromBuiltinData ctx)
    )

-------------------------------------------------------------------------------
-- On-chain target checks
-------------------------------------------------------------------------------

{-# INLINEABLE meetsTarget #-}

{- | @meetsTarget txI tgt@ holds when the transaction produces an output
  satisfying @tgt@: sufficient value to the right address, and (for script
  targets) the correct inline datum.
-}
meetsTarget :: TxInfo -> EscrowTarget -> Bool
meetsTarget txI target = case target of
  PaymentPubKeyTarget pkh vl ->
    valuePaidToPkh txI pkh `geq` vl
  ScriptTarget vh dat vl ->
    case scriptOutputAt txI vh of
      Nothing -> traceError "SNF" -- Script output not found
      Just (odat, ovl) ->
        case odat of
          OutputDatum (Datum d) -> d == getDatum dat && ovl `geq` vl
          _ -> traceError "WDT" -- Wrong datum type: expected inline

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

{-# INLINEABLE valuePaidToPkh #-}

-- | Sum of values in outputs whose payment credential matches the given PKH.
valuePaidToPkh :: TxInfo -> PubKeyHash -> Value
valuePaidToPkh txI pkh =
  foldr
    (\o acc -> if pkhMatchesAddress pkh (txOutAddress o) then txOutValue o + acc else acc)
    zero
    (txInfoOutputs txI)

{-# INLINEABLE pkhMatchesAddress #-}
pkhMatchesAddress :: PubKeyHash -> Address -> Bool
pkhMatchesAddress pkh addr = case addressCredential addr of
  PubKeyCredential pkh' -> pkh' == pkh
  _ -> False

{-# INLINEABLE scriptOutputAt #-}

{- | Find the first output sent to a script identified by its ScriptHash,
  returning its output datum and value.
-}
scriptOutputAt :: TxInfo -> ScriptHash -> Maybe (OutputDatum, Value)
scriptOutputAt txI vh = go (txInfoOutputs txI)
 where
  go [] = Nothing
  go (o : os) = case addressCredential (txOutAddress o) of
    ScriptCredential vh'
      | vh' == vh -> Just (txOutDatum o, txOutValue o)
    _ -> go os
