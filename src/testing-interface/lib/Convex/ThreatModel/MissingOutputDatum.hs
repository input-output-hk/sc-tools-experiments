{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Missing Output Datum vulnerabilities.

A Missing Output Datum Attack targets state-machine validators that require a
continuation output to carry a valid datum. If the validator does not enforce
that requirement, an attacker can remove the datum from the continuation
output and still have the transaction validate.

== Consequences ==

1. __State corruption__: The next contract state cannot be reconstructed from
   the continuation output.

2. __Permanent fund locking__: Future spends may fail because the validator
   cannot decode the expected state from a missing datum.

== Mitigation ==

A secure validator should explicitly reject continuation outputs without datum
(e.g. @NoOutputDatum@) and ensure stateful outputs always include valid datum.

This threat model mutates a continuation output by replacing its datum with
@TxOutDatumNone@. If the transaction still validates, the script may be
vulnerable.
-}
module Convex.ThreatModel.MissingOutputDatum (
  missingOutputDatumAttack,
) where

import Convex.ThreatModel

{- | Check for Missing Output Datum vulnerabilities.

For a transaction that spends a script input and creates a continuation output
back to the same script address with a datum:

* Remove the continuation output datum (@TxOutDatumNone@)
* If the transaction still validates, the script does not enforce that
  continuation outputs carry state datum.
-}
missingOutputDatumAttack :: ThreatModel ()
missingOutputDatumAttack = Named "Missing Output Datum Attack" $ do
  -- Precondition: a script input is spent, so a validator runs.
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)
  let scriptAddr = addressOf scriptInput

  -- Candidate targets: continuation outputs back to the same script address
  -- that currently have some datum.
  outputs <- getTxOutputs
  let continuationOutputsWithDatum =
        filter
          (\o -> addressOf o == scriptAddr && hasOutputDatum o)
          outputs

  threatPrecondition $ ensure (not $ null continuationOutputsWithDatum)

  target <- pickAny continuationOutputsWithDatum

  counterexampleTM $
    paragraph
      [ "The transaction spends a script input at"
      , show (prettyAddress scriptAddr)
      , "and creates a continuation output with datum."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if the continuation output at index"
      , show (outputIx target)
      , "can have its datum removed (TxOutDatumNone) while still validating."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script does not enforce datum presence on"
      , "continuation outputs. This can break state tracking and potentially"
      , "lock funds in an unspendable state."
      ]

  -- This SHOULD fail. If it validates, the script is vulnerable.
  shouldNotValidate $ changeDatumOf target TxOutDatumNone

-- | True when an output carries any datum variant except TxOutDatumNone.
hasOutputDatum :: Output -> Bool
hasOutputDatum output =
  case datumOfTxOut (outputTxOut output) of
    TxOutDatumNone -> False
    _ -> True
