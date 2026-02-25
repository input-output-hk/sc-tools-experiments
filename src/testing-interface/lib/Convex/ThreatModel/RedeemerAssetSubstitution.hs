{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Redeemer Asset Substitution vulnerabilities.

A Redeemer Asset Substitution Attack exploits validators that trust asset
identifiers (policy IDs or token names) provided in the redeemer without
proper validation against the datum or transaction outputs.

== Vulnerability Pattern ==

A vulnerable validator might accept a redeemer like:

@
SellRedeemer { sold_policy_id: ByteArray, sold_token_name: ByteArray }
@

And only check:
@
// VULNERABLE: Trusts redeemer-provided asset without datum cross-check
let token = find_token_in_inputs(redeemer.sold_policy_id, redeemer.sold_token_name)
expect token.quantity > 0
@

Without verifying that the provided asset matches what was actually intended
(e.g., a specific token name stored in the datum).

== Real-world Example: Purchase Offer CTF ==

The @purchase_offer@ CTF contract stores a desired policy ID and an optional
token name in the datum:

@
Datum { owner: Address, desired_policy_id: PolicyId, desired_token_name: Option<ByteArray> }
@

When @desired_token_name@ is @None@, the validator accepts ANY token from
that policy. An attacker can:

1. See an offer for a valuable NFT (e.g., "RareNFT") from policy P
2. Mint a worthless token "WorthlessJunk" under the same policy P
3. Fulfill the offer with "WorthlessJunk" instead of "RareNFT"
4. Claim the locked ADA, leaving the victim with a worthless token

== Consequences ==

1. __Asset theft__: Attackers fulfill offers with worthless tokens
2. __Protocol manipulation__: Wrong assets can satisfy contract conditions
3. __Value extraction__: Locked funds can be drained with fake tokens

== Mitigation ==

A secure validator should:

- Store specific asset identifiers in the datum, not rely on redeemer
- Always validate redeemer-provided values against datum or script context
- Use token name in datum when specificity is required
- Never trust attacker-controlled redeemer data for value checks

This threat model tests if modifying ByteString fields in the redeemer
causes the transaction to fail validation. If the transaction still
validates with modified asset references, the validator may be vulnerable.
-}
module Convex.ThreatModel.RedeemerAssetSubstitution (
  -- * Threat models
  redeemerAssetSubstitution,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Data.ByteString qualified as BS

{- | Check for Redeemer Asset Substitution vulnerabilities.

This threat model finds script inputs, extracts their redeemers, and attempts
to substitute ByteString fields (which could be policy IDs or token names)
with different values. If the transaction still validates after modification,
the validator may be trusting attacker-controlled redeemer data.

The test modifies ByteString fields in the redeemer ScriptData structure:
- Replaces non-empty bytestrings with empty bytestrings
- Replaces empty bytestrings with dummy bytes

If the modified transaction validates, the contract is likely vulnerable
to asset substitution attacks.

Usage:
@
  threatPrecondition $ redeemerAssetSubstitution
@
-}
redeemerAssetSubstitution :: ThreatModel ()
redeemerAssetSubstitution = do
  -- Find a script input (non-key address input)
  input <- anyInputSuchThat (not . isKeyAddressAny . addressOf)

  -- Get the redeemer for this input
  redeemer <-
    getRedeemer input >>= \case
      Nothing -> failPrecondition "No redeemer found for script input - skipping"
      Just redeemer' -> pure redeemer'

  -- Try to substitute ByteString fields in the redeemer
  modifiedRedeemer <- case substituteByteStrings redeemer of
    [] -> failPrecondition "No ByteString fields found in redeemer to substitute - skipping"
    (modified : _) -> pure modified

  counterexampleTM $
    paragraph
      [ "Testing Redeemer Asset Substitution vulnerability:"
      , "Modifying ByteString fields in the redeemer to test if"
      , "the validator properly validates asset references."
      ]

  counterexampleTM $
    paragraph
      [ "Original redeemer: " ++ show redeemer
      , "Modified redeemer: " ++ show modifiedRedeemer
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the validator trusts redeemer-provided"
      , "asset identifiers without proper validation."
      , "An attacker could substitute worthless tokens for valuable ones."
      ]

  -- The modified transaction should NOT validate
  -- If it does validate, the contract is vulnerable
  shouldNotValidate $ changeRedeemerOf input modifiedRedeemer

{- | Substitute ByteString fields in ScriptData.

Walks the ScriptData structure and produces variants where ByteString
fields are replaced with different values:
- Non-empty bytestrings are replaced with empty bytestrings
- Empty bytestrings are replaced with "AAAA" (dummy bytes)

Returns a list of modified ScriptData values (one per ByteString field found).
-}
substituteByteStrings :: C.ScriptData -> [C.ScriptData]
substituteByteStrings = go
 where
  go :: C.ScriptData -> [C.ScriptData]
  go sd = case sd of
    C.ScriptDataBytes bs
      | BS.null bs -> [C.ScriptDataBytes "AAAA"] -- Replace empty with dummy
      | otherwise -> [C.ScriptDataBytes BS.empty] -- Replace non-empty with empty
    C.ScriptDataConstructor n fields ->
      -- For each field position, generate variants where that field is modified
      [ C.ScriptDataConstructor n (replaceAt i modified fields)
      | (i, field) <- zip [0 ..] fields
      , modified <- go field
      ]
    C.ScriptDataList items ->
      [ C.ScriptDataList (replaceAt i modified items)
      | (i, item) <- zip [0 ..] items
      , modified <- go item
      ]
    C.ScriptDataMap pairs ->
      -- Substitute in values (keys are usually not asset references)
      [ C.ScriptDataMap (replaceAt i (k, modified) pairs)
      | (i, (k, v)) <- zip [0 ..] pairs
      , modified <- go v
      ]
    -- Number types don't contain asset references
    C.ScriptDataNumber _ -> []

  replaceAt :: Int -> a -> [a] -> [a]
  replaceAt _ _ [] = []
  replaceAt 0 x (_ : xs) = x : xs
  replaceAt n x (y : ys) = y : replaceAt (n - 1) x ys
