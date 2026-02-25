{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Large Data Attack vulnerabilities.

A Large Data Attack exploits permissive @FromData@ parsers in Plutus validators
that ignore extra fields when deserializing @Constr@ data. If a validator's
datum parser only checks the fields it expects and ignores additional ones,
an attacker can "bloat" the datum with extra fields while preserving the
validator's interpretation.

== Consequences ==

1. __Increased execution costs__: Processing bloated datums wastes CPU/memory
   execution units, making transactions more expensive.

2. __Permanent fund locking__: If the datum is bloated sufficiently:

   - Deserializing the datum may exceed execution unit limits
   - The transaction required to spend the UTxO may exceed protocol size limits

   In these cases, the UTxO becomes __permanently unspendable__ and funds
   are locked forever with no possibility of recovery.

== Root Cause ==

'unstableMakeIsData' and 'makeIsDataIndexed' generate parsers that use
wildcard patterns for constructor fields:

@
case (index, args) of
  (0, _) -> MyConstructor  -- The "_" ignores ALL extra fields!
@

This means @Constr 0 []@ and @Constr 0 [junk1, junk2, ..., junk10000]@ both
parse to the same value, allowing attackers to inject arbitrary data.

== Mitigation ==

A secure validator should either:

- Use strict manual @FromData@ instances that check field count exactly
- Validate the datum hash matches an expected value
- Check datum structure explicitly in the validator logic

This threat model tests if a script output with an inline datum still validates
when additional fields are appended to the datum's @Constr@ data structure.
If it does, the validator has a Large Data Attack vulnerability.
-}
module Convex.ThreatModel.LargeData (
  largeDataAttack,
  largeDataAttackWith,
  bloatData,
) where

import Convex.ThreatModel

{- | Check for Large Data Attack vulnerabilities with 1000 extra fields.

This is the default configuration that appends 1000 extra @ScriptDataNumber 42@
fields to any inline datum on a script output. If the transaction still
validates, the script's datum parser is permissive and vulnerable.
-}
largeDataAttack :: ThreatModel ()
largeDataAttack = largeDataAttackWith 1000

{- | Check for Large Data Attack vulnerabilities with a configurable number
of extra fields.

For a transaction with script outputs containing inline datums:

* Try bloating the datum by appending @n@ extra fields
* If the transaction still validates, the script doesn't strictly validate
  its datum structure - it only checks expected fields and ignores extras.

This catches a vulnerability where different parsers may interpret the same
on-chain data differently, leading to potential exploits.
-}
largeDataAttackWith :: Int -> ThreatModel ()
largeDataAttackWith n = do
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

  let bloatedDatum = bloatData n originalDatum

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "with an inline datum."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if the datum can be bloated with"
      , show n
      , "extra fields while still passing validation."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script's FromData parser is permissive"
      , "and ignores extra Constr fields. An attacker could exploit this"
      , "to make a single datum satisfy multiple validators,"
      , "or to bypass certain datum-based checks."
      ]

  -- Try to validate with the bloated datum
  shouldNotValidate $ changeDatumOf target (toInlineDatum bloatedDatum)

{- | Bloat a @ScriptData@ value by appending extra fields to a @Constr@.

For @ScriptDataConstructor idx fields@, appends @n@ copies of
@ScriptDataNumber 42@ to the fields list.

For other @ScriptData@ variants (Map, List, Number, Bytes), returns
the value unchanged since they don't have the Constr structure that
typical FromData instances parse.
-}
bloatData :: Int -> ScriptData -> ScriptData
bloatData n sd = case sd of
  ScriptDataConstructor idx fields ->
    let extraFields = replicate n (ScriptDataNumber 42)
     in ScriptDataConstructor idx (fields ++ extraFields)
  -- Other cases: return unchanged
  _ -> sd

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
