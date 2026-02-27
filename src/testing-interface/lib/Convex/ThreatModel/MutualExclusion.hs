{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Mutual Exclusion vulnerabilities.

A Mutual Exclusion Attack exploits validators that use @list.find@ or similar
functions to locate "their" continuation output without enforcing uniqueness.
When multiple inputs try to match outputs by property (e.g., same owner, same
script address), having duplicate outputs allows cross-matching between
different inputs.

== Example Vulnerability ==

Consider an account validator that locates its continuation by finding an
output with the same owner:

@
  -- Aiken pseudocode
  let my_output = outputs |> list.find(fn(o) { o.datum.owner == my_owner })
@

If an attacker creates two identical outputs, two different account inputs
can both "find" the same output (or each find a different one that doesn't
actually correspond to their input).

== Attack Scenario ==

1. Transaction spends Account A (owner: Alice) and Account B (owner: Bob)
2. Original outputs: Output A' (owner: Alice), Output B' (owner: Bob)
3. Attack: Duplicate Output A' so we have two outputs with owner: Alice
4. Now Account A and Account B can both claim Output A' as "theirs" since
   list.find returns the first match
5. This breaks the 1:1 correspondence between inputs and outputs

== Consequences ==

1. __Cross-matching__: Input A claims Output B's value, Input B claims nothing
2. __State corruption__: Multiple inputs modify the same output
3. __Fund theft__: Attacker can redirect funds by manipulating which input
   matches which output

== Root Cause ==

Validators that:
- Use @list.find@ to locate continuations without enforcing uniqueness
- Match outputs by datum properties without checking index correspondence
- Don't verify that each input has exactly one matching output

== Mitigation ==

A secure validator should:
- Use index-based matching (output[i] corresponds to input[i])
- Verify no duplicate outputs exist with the same matching criteria
- Use @list.filter@ and check exactly one result

This threat model tests if duplicating a script continuation output still
allows the transaction to validate. If it does, the validator has a
Mutual Exclusion vulnerability.
-}
module Convex.ThreatModel.MutualExclusion (
  mutualExclusionAttack,
) where

import Convex.ThreatModel

{- | Check for Mutual Exclusion vulnerabilities by duplicating script outputs.

For a transaction with script continuation outputs:

* Find a script output (continuation) that goes back to a script address
* Duplicate it — add another output with the SAME address, value, and datum
* If the transaction still validates, the script doesn't properly enforce
  mutual exclusion between inputs and outputs

This catches vulnerability patterns in bank_02 and bank_03 where multiple
account inputs can cross-match outputs because the validator uses list.find
without enforcing uniqueness.
-}
mutualExclusionAttack :: ThreatModel ()
mutualExclusionAttack = Named "Mutual Exclusion Attack" $ do
  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs (NOT key addresses) - these are continuations
  let scriptOutputs = filter (not . isKeyAddressAny . addressOf) outputs

  -- Precondition: there must be at least one script output to duplicate
  threatPrecondition $ ensure (not $ null scriptOutputs)

  -- Pick a target script output to duplicate
  target <- pickAny scriptOutputs

  -- Get the details of the target output
  let targetAddr = addressOf target
      targetValue = valueOf target
      targetRefScript = refScriptOf target

  -- Get the datum from the output (need to handle the Output wrapper)
  let targetDatum = case datumOfTxOut (outputTxOut target) of
        TxOutDatumNone -> TxOutDatumNone
        TxOutDatumHash s h -> TxOutDatumHash s h
        TxOutDatumInline s d -> TxOutDatumInline s d
        TxOutSupplementalDatum s d -> TxOutSupplementalDatum s d

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "going to"
      , show $ prettyAddress targetAddr
      , "."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if this output can be duplicated - adding another output with"
      , "IDENTICAL address, value, and datum."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script has a Mutual Exclusion vulnerability."
      , "Multiple script inputs could cross-match outputs when using list.find"
      , "to locate 'their' continuation, since duplicate outputs would match"
      , "the same criteria."
      ]

  counterexampleTM $
    paragraph
      [ "An attacker could exploit this to:"
      , "1) Have multiple inputs claim the same output as 'theirs'"
      , "2) Break the 1:1 correspondence between inputs and outputs"
      , "3) Redirect funds by manipulating input-output matching"
      ]

  -- The attack: add a duplicate output with the same address, value, datum
  -- If the tx validates with duplicate continuation outputs, the validator
  -- can't properly match inputs to outputs
  shouldNotValidate $ addOutput targetAddr targetValue targetDatum targetRefScript
