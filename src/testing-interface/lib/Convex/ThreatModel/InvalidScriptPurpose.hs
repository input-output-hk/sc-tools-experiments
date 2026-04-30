{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Invalid Script Purpose vulnerabilities.

An Invalid Script Purpose Attack reuses a spending validator as a minting
policy. If the script does not strictly check its purpose, it may validate
under @MintingScript@ context even though it was intended to run only under
@SpendingScript@ context.

== Consequences ==

1. __Authorization bypass__: Spending-specific checks may be skipped when the
   same script is executed under minting purpose.

2. __Unexpected code paths__: Purpose-dependent logic can be triggered in ways
   that were never intended by contract authors.

== Mitigation ==

A secure spending validator should explicitly reject non-spending purposes,
for example by matching only on @SpendingScript@ and failing otherwise.

This threat model mutates a valid transaction by adding a mint action that
executes the provided Plutus V3 script as a minting policy. If the modified
transaction still validates, the script may be vulnerable to purpose confusion.
-}
module Convex.ThreatModel.InvalidScriptPurpose (
  invalidScriptPurposeAttack,
  invalidScriptPurposeAttackWith,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Convex.ThreatModel.Cardano.Api (IsPlutusScriptInEra)
import Convex.ThreatModel.TxModifier (addPlutusScriptMint)
import GHC.Exts (fromList)

{- | Default Invalid Script Purpose attack for Plutus V3 scripts.

Uses a unit-style redeemer (@Constr 0 []@), mints quantity 1, and uses a test
asset name @"deadbeef"@.
-}
invalidScriptPurposeAttack
  :: (IsPlutusScriptInEra lang)
  => C.PlutusScript lang
  -> ThreatModel ()
invalidScriptPurposeAttack =
  invalidScriptPurposeAttackWith
    (C.ScriptDataConstructor 0 [])
    (C.UnsafeAssetName "deadbeef")
    (C.Quantity 1)

{- | Invalid Script Purpose attack with configurable redeemer/asset/quantity.

Given a script intended for spending validation, this threat model:

1. Requires that the transaction spends at least one script input
2. Selects a key-address output as recipient for minted tokens
3. Adds minting under the provided script (forcing @MintingScript@ purpose)
4. Updates the selected output value to include minted tokens
5. Expects the modified transaction to fail validation

If it validates, the contract may accept an unintended script purpose.
-}
invalidScriptPurposeAttackWith
  :: (IsPlutusScriptInEra lang)
  => C.ScriptData
  -> C.AssetName
  -> C.Quantity
  -> C.PlutusScript lang
  -> ThreatModel ()
invalidScriptPurposeAttackWith redeemer assetName quantity spendingValidator = Named "Invalid Script Purpose Attack (V3)" $ do
  -- Precondition: at least one script input must be spent so a script validator runs.
  _ <- anyInputSuchThat (not . isKeyAddressAny . addressOf)

  -- Prefer a key-address output to receive minted test tokens.
  output <- anyOutputSuchThat (isKeyAddressAny . addressOf)

  let policyId = C.PolicyId $ hashScript (C.PlutusScript plutusScriptVersion spendingValidator)
      mintedValue = fromList [(C.AssetId policyId assetName, quantity)]
      newValue = valueOf output <> mintedValue

  counterexampleTM $
    paragraph
      [ "Testing script-purpose confusion by executing a spending validator"
      , "as a minting policy in the same transaction."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script accepted MintingScript context where"
      , "SpendingScript was expected. This can lead to authorization bypass"
      , "or unintended purpose-dependent behavior."
      ]

  -- This SHOULD fail. If it validates, the script is vulnerable.
  shouldNotValidate $
    changeValueOf output newValue
      <> addPlutusScriptMint spendingValidator assetName quantity redeemer
