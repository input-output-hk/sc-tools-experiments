{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting missing integer boundary checks.

A Negative Integer Attack exploits validators that don't check integer bounds
(e.g., @balance >= 0@). The attack negates integer fields in output datums,
which may reveal that the validator allows negative values where only positive
values make semantic sense.

== Consequences ==

1. __Logical state corruption__: If a validator allows negative balances,
   users can withdraw more than they deposited, draining funds from a pool.

2. __Protocol invariant violation__: Counters, timestamps, or other fields
   that should be monotonic or non-negative can be corrupted.

== Vulnerable Patterns ==

=== Pattern: Missing balance check ===

@
// Vulnerable: no check that balance >= 0
let new_balance = input_balance - withdrawal_amount
expect output_datum.balance == new_balance
@

An attacker with @balance = 0@ can withdraw funds, creating @balance = -100@.
The validator doesn't reject this because it never checks @balance >= 0@.

== Mitigation ==

A secure validator should:

- Explicitly check @balance >= 0@ or appropriate bounds for all integer fields
- Validate that counters only increase (or decrease within bounds)
- Use unsigned integers where semantically appropriate (though Plutus uses Integer)

This threat model tests if a script output with an inline datum still validates
when integer fields are negated.
-}
module Convex.ThreatModel.NegativeInteger (
  -- * Negative integer attack
  negativeIntegerAttack,
  negateIntegers,
) where

import Convex.ThreatModel

{- | Check for missing integer boundary checks.

For a transaction with script outputs containing inline datums:

* Recursively negate all @ScriptDataNumber@ fields in the datum
* If the transaction still validates, the script doesn't enforce
  proper bounds checking on integer fields.

This catches vulnerabilities where validators allow negative values
for fields like balances, counters, or timestamps that should be non-negative.

@
negativeIntegerAttack  -- Negate all integers in the datum
@
-}
negativeIntegerAttack :: ThreatModel ()
negativeIntegerAttack = do
  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs with inline datums
  let scriptOutputsWithDatum = filter isScriptOutputWithInlineDatum outputs

  -- Precondition: there must be at least one script output with inline datum
  threatPrecondition $ ensure (not $ null scriptOutputsWithDatum)

  -- Pick a target output
  target <- pickAny scriptOutputsWithDatum

  -- Extract the inline datum (we know it exists due to the filter)
  originalDatum <- case getInlineDatum target of
    Nothing -> failPrecondition "Script output missing inline datum"
    Just originalDatum' -> pure originalDatum'

  let negatedDatum = negateIntegers originalDatum

  -- Only proceed if something actually changed (datum has integers to negate)
  threatPrecondition $ ensure (negatedDatum /= originalDatum)

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "with an inline datum containing integer fields."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if negating the integers in the datum"
      , "still passes validation."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script doesn't enforce integer bounds."
      , "An attacker could exploit this to:"
      , "1) Create negative balances (withdraw more than deposited)"
      , "2) Corrupt counters or timestamps"
      , "3) Violate protocol invariants"
      ]

  -- Try to validate with the negated datum
  shouldNotValidate $ changeDatumOf target (toInlineDatum negatedDatum)

{- | Recursively negate all integer fields in a @ScriptData@ value.

For @ScriptDataNumber n@, returns @ScriptDataNumber (negate n)@.

Recursively processes @ScriptDataConstructor@ fields, lists, and maps.

For other @ScriptData@ variants (Bytes), returns the value unchanged.
-}
negateIntegers :: ScriptData -> ScriptData
negateIntegers (ScriptDataConstructor idx fields) =
  ScriptDataConstructor idx (map negateIntegers fields)
negateIntegers (ScriptDataList items) =
  ScriptDataList (map negateIntegers items)
negateIntegers (ScriptDataMap entries) =
  ScriptDataMap [(negateIntegers k, negateIntegers v) | (k, v) <- entries]
negateIntegers (ScriptDataNumber n) =
  ScriptDataNumber (negate n)
negateIntegers x = x -- bytes, etc. unchanged

-- | Check if an output is a script output with an inline datum.
isScriptOutputWithInlineDatum :: Output -> Bool
isScriptOutputWithInlineDatum output =
  not (isKeyAddressAny (addressOf output)) && hasInlineDatum output

-- | Check if an output has an inline datum.
hasInlineDatum :: Output -> Bool
hasInlineDatum output =
  case datumOfTxOut (outputTxOut output) of
    TxOutDatumInline{} -> True
    _ -> False

-- | Extract the inline datum from an output if present.
getInlineDatum :: Output -> Maybe ScriptData
getInlineDatum output =
  case datumOfTxOut (outputTxOut output) of
    TxOutDatumInline _ hashableData -> Just (getScriptData hashableData)
    _ -> Nothing

-- | Convert a @ScriptData@ to an inline @Datum@ (TxOutDatum CtxTx Era).
toInlineDatum :: ScriptData -> Datum
toInlineDatum sd =
  TxOutDatumInline BabbageEraOnwardsConway (unsafeHashableScriptData sd)
