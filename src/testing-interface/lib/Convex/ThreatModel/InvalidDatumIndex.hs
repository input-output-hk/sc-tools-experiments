{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Invalid Datum Index vulnerabilities.

An Invalid Datum Index Attack mutates the constructor index of a @Constr@ datum
on a script output to a value outside the expected range. If a validator's
@FromData@ parser uses a wildcard or permissive @otherwise@ branch when
deserialising the constructor index, an attacker can supply an invalid index
that still matches a catch-all and is interpreted as a legitimate state.

== Consequences ==

1. __State confusion__: If the out-of-range index accidentally matches a
   catch-all or default branch in @unsafeFromBuiltinData@, the validator may
   interpret the datum as a valid (but semantically wrong) state, allowing
   unintended transitions or fund extraction.

2. __Permanent fund locking__: If the invalid index triggers a script error at
   spend time, any UTxO locked with that corrupted datum becomes permanently
   unspendable.

== Root Cause ==

Validators that use @unsafeFromBuiltinData@ or manually pattern-match on
constructor indices without explicitly rejecting unexpected values are at risk.
For example:

@
case index of
  0 -> Pinged
  1 -> Ponged
  _ -> Stopped   -- catch-all silently accepts ANY other index!
@

This means @Constr 99 []@ would decode as @Stopped@, bypassing any guard that
should have rejected it.

== Mitigation ==

A secure validator should explicitly enumerate all valid indices and call
@P.traceError@ (or equivalent) for any unexpected constructor index:

@
case index of
  0 -> Pinged
  1 -> Ponged
  2 -> Stopped
  _ -> P.traceError "PingPongState: invalid index"
@

This threat model tests whether a script output with an inline datum still
validates when the @Constr@ index is replaced with an out-of-range value.
If it does, the validator has an Invalid Datum Index vulnerability.
-}
module Convex.ThreatModel.InvalidDatumIndex (
  invalidDatumIndexAttack,
  invalidDatumIndexAttackWith,
  replaceConstrIndex,
) where

import Convex.ThreatModel

{- | Check for Invalid Datum Index vulnerabilities using constructor index 5.

This is the default configuration, which replaces the constructor index of any
inline @Constr@ datum on a script output with @5@. Valid PingPong indices are
0 (Pinged), 1 (Ponged), and 2 (Stopped), so @5@ is safely out-of-range for all
known state machines in this codebase. If the transaction still validates, the
validator has a permissive datum index check.
-}
invalidDatumIndexAttack :: ThreatModel ()
invalidDatumIndexAttack = invalidDatumIndexAttackWith 5

{- | Check for Invalid Datum Index vulnerabilities with a configurable
constructor index.

For a transaction with script outputs containing inline datums:

* Replace the @Constr@ index of the datum with @invalidIdx@
* Leave the constructor fields unchanged so any field parsing still succeeds
* If the transaction still validates, the validator does not reject
  out-of-range constructor indices — it may have a permissive catch-all.

Choose @invalidIdx@ to be outside the range of all valid constructors for the
script under test (e.g., @5@ for a 3-constructor type, @99@ for extra clarity).
-}
invalidDatumIndexAttackWith :: Integer -> ThreatModel ()
invalidDatumIndexAttackWith invalidIdx = Named ("Invalid Datum Index Attack (index " ++ show invalidIdx ++ ")") $ do
  -- Precondition: transaction must spend a script input (otherwise no validator runs)
  _ <- anyInputSuchThat (not . isKeyAddressAny . addressOf)

  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs with inline datums that carry a Constr datum
  let scriptOutputsWithConstr = filter isScriptOutputWithConstrInlineDatum outputs

  -- Precondition: there must be at least one eligible target output
  threatPrecondition $ ensure (not $ null scriptOutputsWithConstr)

  -- Pick a target output
  target <- pickAny scriptOutputsWithConstr

  -- Extract the inline datum (we know it exists due to the filter above)
  originalDatum <- case getInlineDatum target of
    Nothing -> failPrecondition "Script output missing inline datum"
    Just d -> pure d

  let mutatedDatum = replaceConstrIndex invalidIdx originalDatum

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "with an inline Constr datum."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if the datum's constructor index can be replaced with"
      , show invalidIdx
      , "while the fields are left unchanged, and the transaction still validates."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script's FromData parser accepts out-of-range"
      , "constructor indices (e.g., via a catch-all branch). An attacker could"
      , "exploit this to:"
      , "1) Confuse the validator about which state the datum represents"
      , "2) Bypass state-transition guards that depend on the constructor index"
      , "3) Lock funds permanently with an unspendable corrupted datum"
      ]

  -- This SHOULD fail - if it validates, the contract is vulnerable.
  shouldNotValidate $ changeDatumOf target (toInlineDatum mutatedDatum)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

{- | Replace the constructor index of a @ScriptDataConstructor@ with @newIdx@,
preserving all fields.

For other @ScriptData@ variants (@Map@, @List@, @Number@, @Bytes@) the value
is returned unchanged and the precondition filter above will have already
excluded non-Constr datums.
-}
replaceConstrIndex :: Integer -> ScriptData -> ScriptData
replaceConstrIndex newIdx sd = case sd of
  ScriptDataConstructor _idx fields -> ScriptDataConstructor newIdx fields
  _ -> sd

-- | True when the output is at a script address and has an inline Constr datum.
isScriptOutputWithConstrInlineDatum :: Output -> Bool
isScriptOutputWithConstrInlineDatum output =
  not (isKeyAddressAny (addressOf output))
    && case getInlineDatum output of
      Just (ScriptDataConstructor{}) -> True
      _ -> False

-- | Extract the inline datum from an output, if present.
getInlineDatum :: Output -> Maybe ScriptData
getInlineDatum output =
  case datumOfTxOut (outputTxOut output) of
    TxOutDatumInline _ hashableData -> Just (getScriptData hashableData)
    _ -> Nothing

-- | Wrap a @ScriptData@ as an inline datum for use with @changeDatumOf@.
toInlineDatum :: ScriptData -> Datum
toInlineDatum sd =
  TxOutDatumInline BabbageEraOnwardsConway (unsafeHashableScriptData sd)
