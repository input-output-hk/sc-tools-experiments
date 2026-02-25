{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting duplicate list entry vulnerabilities.

A Duplicate List Entry Attack exploits validators that don't check for uniqueness
in list fields. The attack duplicates entries in list fields within the datum,
which may reveal that the validator allows duplicate entries where uniqueness
should be enforced.

== Consequences ==

1. __Signature bypassing__: In a multisig contract with @signed_users@ list,
   an attacker can sign once and duplicate their entry to fill all required
   signature slots, bypassing the multi-party requirement.

2. __Vote manipulation__: In a voting contract, a single voter could have their
   vote counted multiple times if the voter list isn't checked for duplicates.

3. __Reward gaming__: In reward distribution, a single participant could claim
   multiple reward shares by appearing multiple times in a beneficiary list.

== Vulnerable Patterns ==

=== Pattern: No uniqueness check on signed_users ===

@
// Vulnerable: only checks length, not uniqueness!
expect list.length(output.signed_users) >= required_signatures
@

An attacker who is allowed to sign can sign once, then intercept the transaction
and duplicate their signature to fill all slots.

=== Pattern: Prepend-only list update without duplicate check ===

@
// Vulnerable: just prepends without checking if already in list
let new_signed = list.push(input.signed_users, signer)
expect output.signed_users == new_signed
@

The validator checks that the signer was prepended correctly, but doesn't check
if the signer was already in the list. Multiple Sign transactions with the same
signer create duplicates.

== Mitigation ==

A secure validator should:

- Check for uniqueness before adding to lists: @!list.has(signed_users, new_signer)@
- Validate that list entries are unique in the output datum
- Use sets instead of lists where uniqueness is required

This threat model tests if a script output with an inline datum still validates
when list entries are duplicated.
-}
module Convex.ThreatModel.DuplicateListEntry (
  -- * Duplicate list entry attack
  duplicateListEntryAttack,
  duplicateFirstEntry,
) where

import Convex.ThreatModel

{- | Check for missing uniqueness checks in list fields.

For a transaction with script outputs containing inline datums:

* Recursively find all non-empty @ScriptDataList@ fields in the datum
* Duplicate the first entry of each list
* If the transaction still validates, the script doesn't enforce
  uniqueness in list fields.

This catches vulnerabilities where validators allow duplicate entries
in lists like @signed_users@, @voters@, or @beneficiaries@ where
uniqueness should be enforced.

@
duplicateListEntryAttack  -- Duplicate first entry in all lists
@
-}
duplicateListEntryAttack :: ThreatModel ()
duplicateListEntryAttack = do
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

  let modifiedDatum = duplicateFirstEntry originalDatum

  -- Only proceed if something actually changed (datum has non-empty lists)
  threatPrecondition $ ensure (modifiedDatum /= originalDatum)

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "with an inline datum containing list fields."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if duplicating the first entry in list fields"
      , "still passes validation."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script doesn't enforce list uniqueness."
      , "An attacker could exploit this to:"
      , "1) Bypass multisig requirements by signing once and duplicating"
      , "2) Manipulate votes by duplicating voter entries"
      , "3) Claim multiple rewards by duplicating beneficiary entries"
      ]

  -- Try to validate with the modified datum
  shouldNotValidate $ changeDatumOf target (toInlineDatum modifiedDatum)

{- | Recursively duplicate the first entry in all non-empty list fields.

For @ScriptDataList (x:xs)@, returns @ScriptDataList (x:x:xs)@ - duplicating
the first entry.

Recursively processes @ScriptDataConstructor@ fields, nested lists, and maps.

For other @ScriptData@ variants (Number, Bytes) and empty lists, returns
the value unchanged.

This simulates an attack where:
- A user signs a multisig, adding their PKH to @signed_users = [pkh]@
- The attacker duplicates to @signed_users = [pkh, pkh]@, filling 2 slots with 1 signature
-}
duplicateFirstEntry :: ScriptData -> ScriptData
duplicateFirstEntry (ScriptDataConstructor idx fields) =
  ScriptDataConstructor idx (map duplicateFirstEntry fields)
duplicateFirstEntry (ScriptDataList (x : xs)) =
  ScriptDataList (x : x : xs) -- duplicate first entry!
duplicateFirstEntry (ScriptDataList []) =
  ScriptDataList []
duplicateFirstEntry (ScriptDataMap entries) =
  ScriptDataMap [(duplicateFirstEntry k, duplicateFirstEntry v) | (k, v) <- entries]
duplicateFirstEntry x = x -- bytes, numbers unchanged

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
