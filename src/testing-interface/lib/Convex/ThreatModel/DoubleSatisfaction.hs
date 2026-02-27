{-# LANGUAGE OverloadedStrings #-}

module Convex.ThreatModel.DoubleSatisfaction (
  doubleSatisfaction,
) where

import Data.ByteString (ByteString)
import PlutusTx.Builtins (toBuiltin)

import Convex.ThreatModel

safeScript :: SimpleScript
safeScript = RequireAllOf [] -- TODO: this is not the right script!

{- | Check for double satisfaction vulnerabilities.

  For a transaction with a public key output to an address (the victim) other than the signer
  (the attacker),

  * if you cannot redirect the output to the attacker, i.e. there is a script that
    cares about the output to the victim,
  * but it validates when you bundle the redirected transaction with a "safe script" that spends
    the same amount to the victim, tagging the output with a unique datum,

  then we have found a double satisfaction vulnerability in the script that stopped the first
  modified transaction.

  NOTE: This threat model removes the victim's output entirely and redirects the value to the
  attacker. This works for both Ada-only outputs and outputs with tokens.
-}
doubleSatisfaction :: ThreatModel ()
doubleSatisfaction = Named "Double Satisfaction" $ do
  signer <- keyAddressAny <$> anySigner

  outputs <- getTxOutputs
  let validTarget t = signer /= t && isKeyAddressAny t
  output <- pickAny $ filter (validTarget . addressOf) outputs

  let value = valueOf output
      victimTarget = addressOf output

  counterexampleTM $
    paragraph $
      [ "The transaction above is signed by"
      , show $ prettyAddress signer
      , "and contains an output to"
      , show (prettyAddress victimTarget) ++ "."
      , "The objective is to show that there is a double satisfaction vulnerability"
      , "that allows the signer to steal this output."
      ]

  counterexampleTM $
    paragraph
      [ "First we check that we cannot simply redirect the output to the signer,"
      , "i.e. the script actually cares about this output."
      ]

  -- Precondition: removing the victim's output and paying to the signer should FAIL
  -- because the script enforces the payment to the victim
  threatPrecondition $
    shouldNotValidate $
      removeOutput output
        <> addOutput signer value TxOutDatumNone ReferenceScriptNone

  counterexampleTM $
    paragraph
      [ "Now we try the same thing again, but this time there is another script"
      , "that pays out to the victim and uses a unique datum to identify the payment."
      ]

  -- Attack: add safe script input with protected output, redirect original output to signer
  let uniqueDatum = txOutDatum $ toScriptData (toBuiltin ("SuchSecure" :: ByteString))

  shouldNotValidate $
    addSimpleScriptInput safeScript value ReferenceScriptNone
      <> addOutput victimTarget value uniqueDatum ReferenceScriptNone
      <> removeOutput output
      <> addOutput signer value TxOutDatumNone ReferenceScriptNone
