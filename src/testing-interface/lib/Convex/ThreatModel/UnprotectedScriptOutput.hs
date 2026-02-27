{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting scripts that don't validate output addresses.

Many Plutus scripts validate datum state transitions but forget to check
that outputs actually go to the correct address. This allows an attacker
to redirect funds while satisfying the script's datum requirements.

Example vulnerable pattern:
@
  validator :: Datum -> Redeemer -> ScriptContext -> Bool
  validator oldState action ctx =
    let newState = getOutputDatum ctx
    in validTransition oldState action newState  -- Only checks datum, not address!
@

A secure script should also verify:
@
  && outputGoesToSameScript ctx
  && valueIsPreserved ctx
@
-}
module Convex.ThreatModel.UnprotectedScriptOutput (
  unprotectedScriptOutput,
) where

import Convex.ThreatModel

{- | Check for unprotected script output vulnerabilities.

For a transaction that spends a script UTxO and produces an output back to
the same script address:

* Try redirecting that output to the transaction signer (attacker)
* If the transaction still validates, the script doesn't properly protect
  its outputs - it only validates datum, not the output address.

This catches a common vulnerability pattern where scripts implement state
machine logic but forget to enforce that outputs stay at the script address.
-}
unprotectedScriptOutput :: ThreatModel ()
unprotectedScriptOutput = Named "Unprotected Script Output" $ do
  -- The attacker is one of the transaction signers
  signer <- anySigner

  -- Find a script input (non-key address = script address)
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)
  let scriptAddr = addressOf scriptInput

  -- Find an output going back to the same script address
  outputs <- getTxOutputs
  let scriptOutputs = filter ((== scriptAddr) . addressOf) outputs

  -- Precondition: there must be a continuation output to the script
  -- (otherwise there's nothing to redirect)
  threatPrecondition $ ensure (not $ null scriptOutputs)

  scriptOutput <- pickAny scriptOutputs

  counterexampleTM $
    paragraph
      [ "The transaction spends a script UTxO at"
      , show $ prettyAddress scriptAddr
      , "and produces a continuation output back to the same address."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if this output can be redirected to the signer at"
      , show $ prettyAddress (keyAddressAny signer)
      , "while preserving the datum (to satisfy any datum-based validation)."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script only checks datum state transitions"
      , "but doesn't verify that outputs go to the correct address."
      , "An attacker could steal funds by satisfying datum requirements"
      , "while redirecting the output to their own wallet."
      ]

  -- changeAddressOf preserves the datum, only changing the address
  -- If this validates, the script is vulnerable
  shouldNotValidate $ changeAddressOf scriptOutput (keyAddressAny signer)
