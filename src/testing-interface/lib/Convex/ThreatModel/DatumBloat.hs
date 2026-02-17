{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Datum Bloat Attack vulnerabilities.

A Datum Bloat Attack exploits validators that don't limit the size of data
fields within their datums. Unlike the Large Data Attack (which adds extra
constructor fields), this attack inflates /existing/ fields - specifically
lists and byte strings within the datum structure.

== Consequences ==

1. __Increased execution costs__: Processing bloated datums wastes CPU/memory
   execution units, making transactions more expensive.

2. __Permanent fund locking__: If a list or bytestring field is bloated sufficiently:

   - Deserializing the datum may exceed execution unit limits
   - The transaction required to spend the UTxO may exceed protocol size limits

   In these cases, the UTxO becomes __permanently unspendable__ and funds
   are locked forever with no possibility of recovery.

== Vulnerable Patterns ==

=== Pattern 1: Unbounded list fields ===

@
type Datum {
  owner: VerificationKeyHash,
  messages: List<ByteArray>  -- No list length limit!
}
@

An attacker can append arbitrarily many items to the messages list,
bloating the datum beyond transaction limits. Caught by 'datumListBloatAttack'.

=== Pattern 2: Unbounded ByteString fields ===

@
type Datum {
  owner: VerificationKeyHash,
  messages: List<ByteArray>  -- No ByteArray SIZE limit!
}
@

An attacker can replace small ByteArrays with huge ones (e.g., "Hello" -> 100KB).
Caught by 'datumByteBloatAttack'.

== Mitigation ==

A secure validator should either:

- Enforce maximum field sizes in the validator logic
- Check list lengths explicitly (e.g., @length messages <= maxMessages@)
- Limit ByteArray sizes (e.g., @lengthOfByteString msg <= maxMsgSize@)
- Hash large data instead of storing it inline

This threat model tests if a script output with an inline datum still validates
when list fields are bloated with additional large items, or when byte string
fields are replaced with much larger ones.
-}
module Convex.ThreatModel.DatumBloat (
  -- * List bloating attacks
  datumListBloatAttack,
  datumListBloatAttackWith,
  bloatLists,

  -- * ByteString inflation attacks
  datumByteBloatAttack,
  datumByteBloatAttackWith,
  inflateBytes,
  inflateFirstListItem,
) where

import Convex.ThreatModel
import Data.ByteString qualified as BS

{- | Check for Datum Bloat vulnerabilities with default parameters.

Appends 5 items of 100 bytes each to every list found in the datum.
If the transaction still validates, the script doesn't limit datum field sizes.
-}
datumListBloatAttack :: ThreatModel ()
datumListBloatAttack = datumListBloatAttackWith 5 100

{- | Check for Datum Bloat vulnerabilities with configurable parameters.

For a transaction with script outputs containing inline datums:

* Recursively find all @ScriptDataList@ fields in the datum
* Append @numItems@ large @ScriptDataBytes@ items to each list
* Each appended item is @itemSize@ bytes of 0x42 ('B')
* If the transaction still validates, the script doesn't enforce
  field size limits - it only checks the fields it expects.

This catches vulnerabilities where validators have unbounded list fields
(like a list of messages or a list of signatures) that can be exploited
to bloat the datum beyond spendable limits.

@
datumListBloatAttackWith 5 100  -- Add 5 items of 100 bytes each
datumListBloatAttackWith 10 500 -- More aggressive: 10 items of 500 bytes
@
-}
datumListBloatAttackWith :: Int -> Int -> ThreatModel ()
datumListBloatAttackWith numItems itemSize = do
  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs with inline datums
  let scriptOutputsWithDatum = filter isScriptOutputWithInlineDatum outputs

  -- Precondition: there must be at least one script output with inline datum
  threatPrecondition $ ensure (not $ null scriptOutputsWithDatum)

  -- Pick a target output
  target <- pickAny scriptOutputsWithDatum

  -- Extract the inline datum (we know it exists due to the filter)
  case getInlineDatum target of
    Nothing -> fail "Expected inline datum but found none"
    Just originalDatum -> do
      -- Check if the datum contains any lists to bloat
      unless (containsList originalDatum) $
        fail "Datum contains no list fields to bloat"

      let bloatedDatum = bloatLists numItems itemSize originalDatum

      counterexampleTM $
        paragraph
          [ "The transaction contains a script output at index"
          , show (outputIx target)
          , "with an inline datum containing list fields."
          ]

      counterexampleTM $
        paragraph
          [ "Testing if the lists can be bloated with"
          , show numItems
          , "items of"
          , show itemSize
          , "bytes each while still passing validation."
          ]

      counterexampleTM $
        paragraph
          [ "If this validates, the script doesn't enforce datum field size limits."
          , "An attacker could exploit this to:"
          , "1) Inflate the datum beyond transaction size limits"
          , "2) Increase execution costs for processing the datum"
          , "3) Potentially lock funds permanently if limits are exceeded"
          ]

      -- Try to validate with the bloated datum
      shouldNotValidate $ changeDatumOf target (toInlineDatum bloatedDatum)
 where
  unless False action = action
  unless True _ = pure ()

{- | Recursively bloat all list fields in a @ScriptData@ value.

For @ScriptDataList items@, appends @numItems@ copies of
@ScriptDataBytes (BS.replicate itemSize 0x42)@ to the list.

Recursively processes @ScriptDataConstructor@ fields and nested lists.

For other @ScriptData@ variants (Map, Number, Bytes), returns
the value unchanged.
-}
bloatLists :: Int -> Int -> ScriptData -> ScriptData
bloatLists numItems itemSize = go
 where
  largeItem = ScriptDataBytes (BS.replicate itemSize 0x42)

  go (ScriptDataConstructor idx fields) =
    ScriptDataConstructor idx (map go fields)
  go (ScriptDataList items) =
    ScriptDataList (map go items ++ replicate numItems largeItem)
  go (ScriptDataMap entries) =
    ScriptDataMap [(go k, go v) | (k, v) <- entries]
  go other = other

-- | Check if a @ScriptData@ value contains any list fields.
containsList :: ScriptData -> Bool
containsList (ScriptDataConstructor _ fields) = any containsList fields
containsList (ScriptDataList _) = True
containsList (ScriptDataMap entries) = any (\(k, v) -> containsList k || containsList v) entries
containsList _ = False

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

-- ----------------------------------------------------------------------------
-- ByteString Inflation Attack
-- ----------------------------------------------------------------------------

{- | Test if ByteString fields in the datum can be inflated.

This catches validators that don't limit the size of individual
ByteString fields (e.g., messages, names, arbitrary data).

The attack replaces every @ScriptDataBytes@ field found at any depth
(except the first field of the top-level constructor, typically an owner hash)
with a much larger ByteString.

For a tipjar datum @Con0(owner_hash, [\"Hello\"])@:

* @owner_hash@ is preserved (first field must match for validation)
* @\"Hello\"@ inside the list gets inflated to 10KB of @0x42@
* Result: @Con0(owner_hash, [<10KB bytes>])@
* The validator checks: @list.push([], <10KB bytes>) == [<10KB bytes>]@ → True!

This enables a DoS attack where an attacker can:

1. Create a valid transaction with a small message
2. Intercept/frontrun and replace the message with a huge ByteArray
3. The bloated datum may exceed transaction limits for future spending

Default inflation size is 10,000 bytes (10KB).
-}
datumByteBloatAttack :: ThreatModel ()
datumByteBloatAttack = datumByteBloatAttackWith 10000

{- | Check for ByteString inflation vulnerabilities with configurable size.

This attack is specifically designed to catch validators like tipjar that:
1. Allow adding items to a list
2. Check that @list.push(old_items, new_item) == new_items@
3. But DON'T limit the SIZE of @new_item@

The attack inflates only the FIRST item in lists (typically the newly-added
item), leaving existing items unchanged so the structural check passes.

@
datumByteBloatAttackWith 10000   -- Inflate first list item to 10KB
datumByteBloatAttackWith 50000   -- More aggressive: 50KB
@
-}
datumByteBloatAttackWith :: Int -> ThreatModel ()
datumByteBloatAttackWith inflatedSize = do
  outputs <- getTxOutputs
  let scriptOutputsWithDatum = filter isScriptOutputWithInlineDatum outputs
  threatPrecondition $ ensure (not $ null scriptOutputsWithDatum)
  target <- pickAny scriptOutputsWithDatum
  case getInlineDatum target of
    Nothing -> fail "Expected inline datum"
    Just originalDatum -> do
      let bloatedDatum = inflateFirstListItem inflatedSize originalDatum
      -- Only proceed if something actually changed (datum has list with items to inflate)
      threatPrecondition $ ensure (bloatedDatum /= originalDatum)
      counterexampleTM $
        paragraph
          [ "The transaction contains a script output with an inline datum."
          , "Testing if the first item in list fields can be inflated to"
          , show inflatedSize
          , "bytes while still passing validation."
          ]
      counterexampleTM $
        paragraph
          [ "If this validates, the script doesn't limit ByteString field sizes,"
          , "enabling a datum bloat DoS attack where an attacker can add"
          , "a huge message/data item to bloat the datum beyond spendable limits."
          ]
      shouldNotValidate $ changeDatumOf target (toInlineDatum bloatedDatum)

{- | Replace all @ScriptDataBytes@ with inflated versions.

Preserves the first field of the top-level constructor (typically an
owner/address hash that must match exactly for validation).

Inflates all other @ScriptDataBytes@ found at any depth with a ByteString
of the given size filled with @0x42@ ('B').

For the tipjar use case, this inflates EVERY message in the list, which
changes the structure too much. For validators that do structural checks
like @list.push(old_msgs, new_msg) == new_msgs@, this will fail.

Use 'inflateFirstListItem' for a more targeted attack that only inflates
the first (newest) message in a list.
-}
inflateBytes :: Int -> ScriptData -> ScriptData
inflateBytes size = goTop
 where
  largeBytes = BS.replicate size 0x42

  -- At top level, preserve first field of constructor
  goTop (ScriptDataConstructor idx fields) =
    case fields of
      (first : rest) -> ScriptDataConstructor idx (first : map go rest)
      [] -> ScriptDataConstructor idx []
  goTop other = go other

  -- Recursive case: inflate all ByteStrings
  go (ScriptDataConstructor idx fields) = ScriptDataConstructor idx (map go fields)
  go (ScriptDataList items) = ScriptDataList (map go items)
  go (ScriptDataMap entries) = ScriptDataMap [(go k, go v) | (k, v) <- entries]
  go (ScriptDataBytes _) = ScriptDataBytes largeBytes
  go other = other

{- | Inflate only the FIRST @ScriptDataBytes@ found in lists.

This is a more targeted attack for validators like tipjar that check:
@list.push(input_messages, new_msg) == output_messages@

The validator only cares that the NEW message (head of the list) was
correctly prepended. It doesn't check the SIZE of that message.

For a tipjar datum @Con0(owner_hash, [\"New\", \"Old1\", \"Old2\"])@:

* @owner_hash@ is preserved
* @\"New\"@ (first/newest message) gets inflated to 10KB
* @\"Old1\"@, @\"Old2\"@ are left unchanged (must match input)
* Result: @Con0(owner_hash, [<10KB>, \"Old1\", \"Old2\"])@

The validator check:
* Input: @[\"Old1\", \"Old2\"]@
* @list.push([\"Old1\", \"Old2\"], <10KB>) = [<10KB>, \"Old1\", \"Old2\"]@
* This equals the output! Vulnerability exploited.
-}
inflateFirstListItem :: Int -> ScriptData -> ScriptData
inflateFirstListItem size = goTop
 where
  largeBytes = BS.replicate size 0x42

  -- At top level, preserve first field of constructor (owner hash)
  goTop (ScriptDataConstructor idx fields) =
    case fields of
      (first : rest) -> ScriptDataConstructor idx (first : map goList rest)
      [] -> ScriptDataConstructor idx []
  goTop other = goList other

  -- Find lists and inflate only the first item
  goList (ScriptDataConstructor idx fields) = ScriptDataConstructor idx (map goList fields)
  goList (ScriptDataList (firstItem : restItems)) =
    -- Inflate only the first item in the list, leave rest unchanged
    ScriptDataList (inflateItem firstItem : restItems)
  goList (ScriptDataList []) = ScriptDataList []
  goList (ScriptDataMap entries) = ScriptDataMap [(goList k, goList v) | (k, v) <- entries]
  goList other = other

  -- Inflate a single item (recursively inflate all ByteStrings in it)
  inflateItem (ScriptDataBytes _) = ScriptDataBytes largeBytes
  inflateItem (ScriptDataConstructor idx fields) =
    ScriptDataConstructor idx (map inflateItem fields)
  inflateItem (ScriptDataList items) = ScriptDataList (map inflateItem items)
  inflateItem (ScriptDataMap entries) =
    ScriptDataMap [(inflateItem k, inflateItem v) | (k, v) <- entries]
  inflateItem other = other
