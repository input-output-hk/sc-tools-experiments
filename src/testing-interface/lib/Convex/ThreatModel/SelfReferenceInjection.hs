{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Self-Reference Injection vulnerabilities.

A Self-Reference Injection attack exploits validators that check "pay to address X"
where X comes from the datum. If an attacker can set X to the script's own address,
then the continuation output (which necessarily goes to the script) satisfies the
payment check for free.

== Consequences ==

1. __Free value extraction__: The attacker bypasses payment requirements.
   Instead of paying to the intended recipient, the "payment" is just the
   continuation output that was going to the script anyway.

2. __Protocol violation__: The semantic meaning of "pay to X" is violated.
   For example, in a "king of the hill" contract, the old king never receives
   their rightful payment when overthrown.

== Vulnerable Patterns ==

@
validator spend(datum: Datum, _redeemer: Void, ctx: ScriptContext) {
  // Check that SOME output pays current_beneficiary
  expect Some(out) = list.find(ctx.transaction.outputs, fn(o) {
    o.address == datum.current_beneficiary && o.value >= datum.min_payment
  })
  ...
}
@

If @datum.current_beneficiary@ can be set to the script's own address (either
through initialization or a state transition), the continuation output satisfies
this check automatically.

== Attack Flow ==

1. Set @current_beneficiary@ (or similar address field) to the script address
2. Create a transaction that spends the script UTxO
3. The continuation output satisfies the "payment" check
4. No real payment to the intended recipient occurs

== Mitigation ==

1. __Validate address is different__: Check that the beneficiary address is NOT
   the script's own address.

2. __Use credential type restrictions__: Only allow PubKeyCredential for
   beneficiary fields (not ScriptCredential).

3. __External payment validation__: Check that a SEPARATE output (not the
   continuation) pays the beneficiary.

This threat model:
1. Finds a script input (to identify the script address)
2. Finds continuation outputs with inline datums
3. Replaces address credentials in the datum with the script's own credential
4. Tests if the modified transaction still validates (vulnerability exists!)
-}
module Convex.ThreatModel.SelfReferenceInjection (
  -- * Threat models
  selfReferenceInjection,
  selfReferenceInjectionWith,

  -- * Datum transformation
  injectScriptCredential,
  isAddressLikeStructure,
) where

import Cardano.Ledger.Binary (DecodeAction (Fail))
import Convex.ThreatModel
import Data.ByteString qualified as BS

{- | Check for Self-Reference Injection vulnerabilities.

For a transaction with script inputs and outputs containing inline datums:

* Identifies the script address from the spent script input
* Finds continuation outputs (script outputs with inline datums)
* Replaces address credentials in the datum with the script's own credential
* If the transaction still validates, the script is vulnerable to self-reference

This catches the "king of the hill" vulnerability where setting @current_king@
to the script address allows bypassing the payment requirement.

The attack works because:
1. Script checks "some output pays current_king at least X"
2. When current_king = script_address, the continuation output satisfies this
3. The attacker gets the "king" status without actually paying anyone
-}
selfReferenceInjection :: ThreatModel ()
selfReferenceInjection = selfReferenceInjectionWith False

{- | Check for Self-Reference Injection with configurable verbosity.

@
selfReferenceInjectionWith True  -- Verbose mode with detailed counterexamples
selfReferenceInjectionWith False -- Standard mode
@
-}
selfReferenceInjectionWith :: Bool -> ThreatModel ()
selfReferenceInjectionWith verbose = Named "Self-Reference Injection" $ do
  -- Get all inputs and outputs
  inputs <- getTxInputs
  outputs <- getTxOutputs

  -- Find script inputs (non-key address inputs)
  let scriptInputs = filter (not . isKeyAddressAny . addressOf) inputs

  -- Precondition: must have at least one script input
  threatPrecondition $ ensure (not $ null scriptInputs)

  -- Pick a script input to get the script address
  scriptInput <- pickAny scriptInputs

  -- Extract the script hash from the script address
  let scriptAddr = addressOf scriptInput

  credBytes <- case extractScriptCredential scriptAddr of
    Nothing -> failPrecondition "Script output missing"
    Just credBytes' -> pure credBytes'

  -- Filter to script outputs with inline datums (continuation outputs)
  let continuationOutputs = filter isScriptOutputWithInlineDatum outputs

  -- Precondition: there must be at least one continuation output
  threatPrecondition $ ensure (not $ null continuationOutputs)

  -- Pick a target output
  target <- pickAny continuationOutputs

  -- Extract the inline datum
  originalDatum <- case getInlineDatum target of
    Nothing -> failPrecondition "Script output missing inline datum"
    Just originalDatum' -> pure originalDatum'

  -- Build the script's credential as ScriptData
  -- ScriptCredential = Constr 1 [Bytes script_hash]
  let scriptCredData = ScriptDataConstructor 1 [ScriptDataBytes credBytes]

  -- Try to inject the script credential into address fields
  let modifiedDatum = injectScriptCredential scriptCredData originalDatum

  -- Only proceed if something actually changed
  threatPrecondition $ ensure (modifiedDatum /= originalDatum)

  when verbose $ do
    counterexampleTM $
      paragraph
        [ "The transaction contains a script input at address"
        , show (prettyAddress scriptAddr)
        , "and a continuation output at index"
        , show (outputIx target)
        , "with an inline datum."
        ]

    counterexampleTM $
      paragraph
        [ "Testing if address fields in the datum can be replaced with"
        , "the script's own address while still passing validation."
        ]

  counterexampleTM $
    paragraph
      [ "Self-reference injection: replaced address credentials in datum"
      , "with the script's own credential. If this validates, the script"
      , "doesn't prevent setting address fields to its own address,"
      , "allowing bypass of payment requirements."
      ]

  -- Try to validate with the modified datum
  shouldNotValidate $ changeDatumOf target (toInlineDatum modifiedDatum)
 where
  when False _ = pure ()
  when True action = action

{- | Extract the script credential (28 bytes) from a script address.

Returns Nothing for pubkey addresses.
-}
extractScriptCredential :: AddressAny -> Maybe BS.ByteString
extractScriptCredential addr =
  case addr of
    AddressShelley (ShelleyAddress _ cred _) ->
      case fromShelleyPaymentCredential cred of
        PaymentCredentialByScript sh ->
          Just $ serialiseToRawBytes sh
        PaymentCredentialByKey _ ->
          Nothing
    AddressByron _ ->
      Nothing

{- | Inject a script credential into all address-like structures in a datum.

An address in Plutus is encoded as:
@Constr 0 [credential, staking_credential]@

Where credential is either:
- @Constr 0 [Bytes pubkey_hash]@ (PubKeyCredential)
- @Constr 1 [Bytes script_hash]@ (ScriptCredential)

This function walks the datum and replaces all PubKeyCredential structures
with the given ScriptCredential, simulating an attacker who sets the
beneficiary address to the script's own address.
-}
injectScriptCredential :: ScriptData -> ScriptData -> ScriptData
injectScriptCredential newCred = go
 where
  go (ScriptDataConstructor 0 [cred, stakingCred])
    | isCredentialLike cred =
        -- This looks like a Plutus Address (Constr 0 [credential, staking])
        -- Replace the credential with our script credential
        ScriptDataConstructor 0 [newCred, stakingCred]
  go (ScriptDataConstructor idx fields) =
    ScriptDataConstructor idx (map go fields)
  go (ScriptDataList items) =
    ScriptDataList (map go items)
  go (ScriptDataMap entries) =
    ScriptDataMap [(go k, go v) | (k, v) <- entries]
  go other = other

  -- Check if a ScriptData looks like a Plutus Credential
  -- PubKeyCredential = Constr 0 [Bytes (28 bytes)]
  -- ScriptCredential = Constr 1 [Bytes (28 bytes)]
  isCredentialLike (ScriptDataConstructor n [ScriptDataBytes bs])
    | n `elem` [0, 1] && BS.length bs == 28 = True
  isCredentialLike _ = False

{- | Check if a ScriptData structure looks like a Plutus Address.

A Plutus Address is: @Constr 0 [credential, staking_credential]@

Where:
- credential is @Constr 0|1 [Bytes (28 bytes)]@
- staking_credential is @Constr 0|1 [...]@ or @Constr 0 []@ (None)
-}
isAddressLikeStructure :: ScriptData -> Bool
isAddressLikeStructure (ScriptDataConstructor 0 [cred, _stakingCred]) =
  isCredentialLike cred
 where
  isCredentialLike (ScriptDataConstructor n [ScriptDataBytes bs])
    | n `elem` [0, 1] && BS.length bs == 28 = True
  isCredentialLike _ = False
isAddressLikeStructure _ = False

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
