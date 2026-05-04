{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting missing OutputDatumHash witness vulnerabilities.

This attack mutates a continuation output from inline datum to @TxOutDatumHash@
with a hash that is not present in @txInfoData@. A secure validator that reads
state from output datum hashes must reject this transaction because it cannot
resolve the hash to actual datum bytes.

== Consequences ==

1. __State resolution failure__: The validator cannot decode continuation state.

2. __Potential fund locking__: If invalid continuation outputs are accepted,
   future spends can fail when state cannot be reconstructed.

== Mitigation ==

A secure validator should reject @OutputDatumHash@ values that cannot be found
in the transaction datum map.
-}
module Convex.ThreatModel.OutputDatumHashMissing (
  outputDatumHashMissingAttack,
  outputDatumHashMissingAttackWith,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Convex.Utils.String (unsafeDatumHash)

-- | Default attack using a deterministic orphaned datum hash.
outputDatumHashMissingAttack :: ThreatModel ()
outputDatumHashMissingAttack =
  outputDatumHashMissingAttackWith
    (unsafeDatumHash "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

{- | Attack with configurable orphaned datum hash.

For transactions that spend a script input and create a continuation output with
inline datum at the same script address:

* Replace that output's datum with @TxOutDatumHash@ using @orphanHash@
* Keep the hash absent from @txInfoData@
* If the transaction still validates, the contract does not enforce datum-hash
  resolution safety.
-}
outputDatumHashMissingAttackWith :: C.Hash C.ScriptData -> ThreatModel ()
outputDatumHashMissingAttackWith orphanHash = Named "Output Datum Hash Missing Attack" $ do
  -- Precondition: a script input is spent, so a validator executes.
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)
  let scriptAddr = addressOf scriptInput

  -- Candidate targets: continuation outputs to same script address with inline datum.
  outputs <- getTxOutputs
  let continuationInlineOutputs =
        filter
          (\o -> addressOf o == scriptAddr && hasInlineDatum o)
          outputs

  threatPrecondition $ ensure (not $ null continuationInlineOutputs)

  target <- pickAny continuationInlineOutputs

  counterexampleTM $
    paragraph
      [ "The transaction spends a script input at"
      , show (prettyAddress scriptAddr)
      , "and creates a continuation output with inline datum."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if the output datum at index"
      , show (outputIx target)
      , "can be converted to TxOutDatumHash with an orphaned hash"
      , "that is not present in txInfoData."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script may accept output datum hashes without"
      , "ensuring the hash resolves in the datum map, which can break state"
      , "reconstruction and lead to locked funds."
      ]

  -- This SHOULD fail. If it validates, the script is vulnerable.
  shouldNotValidate $ changeDatumOf target (TxOutDatumHash C.alonzoBasedEra orphanHash)

-- | True when an output uses inline datum.
hasInlineDatum :: Output -> Bool
hasInlineDatum output =
  case datumOfTxOut (outputTxOut output) of
    TxOutDatumInline{} -> True
    _ -> False
