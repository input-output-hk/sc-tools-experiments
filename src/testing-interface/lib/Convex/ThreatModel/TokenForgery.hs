{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Token Forgery vulnerabilities.

A Token Forgery Attack exploits minting policies that are too permissive.
If a minting policy allows tokens to be minted under weak conditions (e.g.,
just requiring any signature), an attacker can mint unauthorized tokens.

== Vulnerability Pattern ==

A vulnerable minting policy might only check:

@
MintValidation -> {
  // VULNERABLE: Anyone who signs can mint!
  list.length(self.extra_signatories) > 0
}
@

This is trivially satisfied by ANY signed transaction, allowing anyone to
forge tokens that should be restricted.

== Consequences ==

1. __Validation token bypass__: If a validator requires a "validation token"
   to prove authorization, attackers can mint their own tokens.

2. __Asset theft__: Forged tokens can be used to satisfy validator checks,
   potentially draining funds.

3. __Protocol manipulation__: In DeFi protocols, forged governance or
   utility tokens can manipulate voting, rewards, or access control.

== Mitigation ==

A secure minting policy should:

- Require specific authorized signers (not just "any signature")
- Check that minting is authorized by a governance mechanism
- Verify minting is part of a valid protocol operation
- Use one-shot minting for unique tokens (NFTs, thread tokens)

This threat model tests if additional tokens can be minted using the same
minting policy that the transaction already uses. If the transaction still
validates with extra minted tokens, the minting policy may be too permissive.
-}
module Convex.ThreatModel.TokenForgery (
  -- * Threat models
  tokenForgeryAttack,
  tokenForgeryAttackWith,

  -- * Helpers
  simpleAlwaysSucceedsMintingPolicyV2,
  simpleTestAssetName,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Convex.ThreatModel.Cardano.Api (IsPlutusScriptInEra)
import Convex.ThreatModel.TxModifier (addPlutusScriptMint)
import GHC.Exts (fromList)
import PlutusLedgerApi.Test.Examples (alwaysSucceedingNAryFunction)

{- | Check for Token Forgery vulnerabilities with a Plutus V2 minting policy.

Given a minting policy and asset name, this threat model attempts to mint
additional tokens with that policy. If the transaction still validates,
the minting policy is too permissive.

Usage:
@
  threatPrecondition $ tokenForgeryAttack mintingPolicy assetName
@

The redeemer used is @Constr 0 []@ (unit), which is common for simple
minting policies. Use 'tokenForgeryAttackWith' for custom redeemers.
-}
tokenForgeryAttack
  :: (IsPlutusScriptInEra lang)
  => C.PlutusScript lang
  -- ^ The minting policy to test
  -> C.AssetName
  -- ^ The asset name to mint
  -> ThreatModel ()
tokenForgeryAttack = tokenForgeryAttackWith unitRedeemer
 where
  unitRedeemer = C.ScriptDataConstructor 0 []

{- | Check for Token Forgery vulnerabilities with a custom redeemer.

This variant allows specifying the redeemer to use when attempting to
mint additional tokens. This is useful when the minting policy expects
a specific redeemer format.

@
  -- Test with MintValidation redeemer (Constr 0 [])
  tokenForgeryAttackWith (ScriptDataConstructor 0 []) mintingPolicy assetName

  -- Test with custom redeemer
  tokenForgeryAttackWith myRedeemer mintingPolicy assetName
@
-}
tokenForgeryAttackWith
  :: (IsPlutusScriptInEra lang)
  => C.ScriptData
  -- ^ Redeemer for the minting policy
  -> C.PlutusScript lang
  -- ^ The minting policy to test
  -> C.AssetName
  -- ^ The asset name to mint
  -> ThreatModel ()
tokenForgeryAttackWith redeemer mintScript assetName = Named "Token Forgery Attack" $ do
  -- Find an output to add the minted tokens to
  -- Prefer a key address output (like the change output)
  output <- anyOutputSuchThat (isKeyAddressAny . addressOf)

  counterexampleTM $
    paragraph
      [ "Testing Token Forgery vulnerability:"
      , "Attempting to mint additional tokens using the provided minting policy."
      , "Adding minted tokens to output at " ++ show (prettyAddress $ addressOf output) ++ "."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the minting policy is too permissive."
      , "An attacker could forge tokens to:"
      , "1) Bypass validation token requirements"
      , "2) Steal assets protected by token checks"
      , "3) Manipulate protocol state"
      ]

  -- Calculate the minted asset value
  let scriptHash = C.hashScript $ C.PlutusScript plutusScriptVersion mintScript
      policyId = C.PolicyId scriptHash
      mintedValue = fromList [(C.AssetId policyId assetName, 1)]
      newValue = valueOf output <> mintedValue

  -- Try to mint one additional token with the given policy and add it to the output
  -- This SHOULD fail - if it validates, the policy is vulnerable
  shouldNotValidate $
    changeValueOf output newValue
      <> addPlutusScriptMint mintScript assetName (C.Quantity 1) redeemer

-- ============================================================================
-- Helper functions for threat model usage
-- ============================================================================

{- | A simple Plutus minting policy that always validates (for testing).

This provides a reusable always-succeeds minting policy suitable for
testing token forgery vulnerabilities. It's commonly used to create
throwaway minting policies when testing spending validators.

Usage:
@
  threatModels = [ tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV3 simpleTestAssetName ]
@
-}
simpleAlwaysSucceedsMintingPolicyV2 :: C.PlutusScript C.PlutusScriptV2
simpleAlwaysSucceedsMintingPolicyV2 =
  C.PlutusScriptSerialised $
    alwaysSucceedingNAryFunction 2

{- | A simple asset name for testing (empty string).

This provides a basic asset name for use with token forgery attacks
and other threat model testing where the asset name is not critical.

The empty asset name is a common convention for test tokens.
-}
simpleTestAssetName :: C.AssetName
simpleTestAssetName = C.UnsafeAssetName ""
