{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Redeemer Asset Substitution vulnerabilities.

= What vulnerability this detects

A Redeemer Asset Substitution Attack exploits validators that trust asset
identifiers (policy IDs or token names) provided in the redeemer without
proper validation against the datum or transaction context.

= Attack scenario

Consider a validator that accepts a redeemer like:

@
SellRedeemer { sold_policy_id: ByteArray, sold_token_name: ByteArray }
@

And only checks:

@
\/\/ VULNERABLE: Trusts redeemer-provided asset without datum cross-check
let token = find_token_in_inputs(redeemer.sold_policy_id, redeemer.sold_token_name)
expect token.quantity > 0
@

Without verifying that the provided asset matches what was actually intended
(e.g., a specific token name stored in the datum).

__Real-world example: Purchase Offer CTF__

The @purchase_offer@ CTF contract stores a desired policy ID and an optional
token name in the datum:

@
Datum { owner: Address, desired_policy_id: PolicyId, desired_token_name: Option\<ByteArray\> }
@

When @desired_token_name@ is @None@, the validator accepts ANY token from
that policy. An attacker can:

1. See an offer for a valuable NFT (e.g., \"RareNFT\") from policy P
2. Acquire a worthless token \"WorthlessJunk\" under the same policy P
3. Fulfill the offer with \"WorthlessJunk\" instead of \"RareNFT\"
4. Claim the locked ADA, leaving the victim with a worthless token

= How this threat model works

This threat model uses a \"swappable pair\" approach that is Phase 1 valid:

1. __Find a script input__ — a non-key address input being spent
2. __Get its redeemer__ — extract the ScriptData redeemer
3. __Extract ByteString fields__ — these are potential token names
4. __Get all transaction outputs__
5. __Find the first output__ with a token @(policyP, originalName)@ where
   @originalName@ matches one of the redeemer ByteStrings
6. __Find a second output__ (different from the first) containing a DIFFERENT
   token @(policyP, otherName)@ from the SAME policy where @otherName \/= originalName@
7. __Swap the tokens__ between the two outputs:
   - Output1: remove @(policyP, originalName)@, add @(policyP, otherName)@
   - Output2: remove @(policyP, otherName)@, add @(policyP, originalName)@
8. __Substitute the redeemer__: replace @originalName@ ByteString with @otherName@ in the redeemer
9. __Check validation__: the modified transaction should NOT validate

If the modified transaction validates (accepting the swapped token names),
the validator is vulnerable because it accepts any token name without
cross-checking the datum.

= Why Phase 1 validity matters

Cardano transactions go through two phases of validation:

- __Phase 1__: Ledger rules checking (value preservation, signatures, etc.)
- __Phase 2__: Script execution (Plutus validators)

Phase 1 enforces that total value in = total value out + fees. A transaction
that claims to send a token that doesn't exist in any input would be rejected
at Phase 1 before the validator script even runs.

By swapping EXISTING tokens between outputs (rather than inventing non-existent
tokens), this threat model creates transactions that pass Phase 1 and actually
reach the validator for Phase 2 execution. This tests the real attack scenario
where an attacker possesses a worthless token from the same collection.

= Preconditions required

The transaction must contain at least two different tokens from the same policy
in different outputs. This naturally happens when:

- The wallet holds multiple tokens from the same policy (e.g., a valuable NFT
  and a worthless one from the same collection)
- Coin selection includes a UTxO containing extra tokens from the same policy
- The fulfill transaction sends one token to the contract owner and returns
  another as change

= How to satisfy preconditions in TestingInterface

When writing a 'Convex.ThreatModel.TestingInterface.TestingInterface' instance,
the @perform@ action for the relevant scenario should ensure the wallet holds
multiple tokens from the same policy.

Example approach:

1. In the setup\/mint action, mint BOTH a \"valuable\" token AND a \"worthless\"
   token from the same policy to the attacker's wallet
2. When the attacker calls @perform@ on the fulfill action, coin selection will
   naturally include the UTxO containing both tokens
3. The fulfill transaction will have one token going to the contract owner's
   output and the other in the change output
4. The threat model can now find the swappable pair and test the vulnerability

This mirrors the real attack scenario: the attacker legitimately possesses a
worthless token from the same NFT collection and uses it to fraudulently
fulfill an offer meant for a valuable token.

= Consequences of the vulnerability

1. __Asset theft__: Attackers fulfill offers with worthless tokens
2. __Protocol manipulation__: Wrong assets can satisfy contract conditions
3. __Value extraction__: Locked funds can be drained with substitute tokens

= Mitigation

A secure validator should:

- Store specific asset identifiers (including token name) in the datum
- Always validate redeemer-provided values against datum or script context
- Never trust attacker-controlled redeemer data for asset identification
- Use token name in datum when specificity is required
-}
module Convex.ThreatModel.RedeemerAssetSubstitution (
  -- * Threat models
  redeemerAssetSubstitution,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Data.ByteString qualified as BS
import Data.Maybe (listToMaybe)
import GHC.Exts (fromList, toList)

{- | Check for Redeemer Asset Substitution vulnerabilities using the swappable-pair approach.

This threat model:

1. Finds a script input and extracts its redeemer
2. Extracts ByteString fields from the redeemer (potential token names)
3. For each ByteString, interprets it as an 'C.AssetName' and looks for an output
   containing a token @(policyP, originalName)@ matching that ByteString
4. Searches for a SECOND output (different from the first) containing a DIFFERENT
   token @(policyP, otherName)@ from the SAME policy
5. Swaps the tokens between the two outputs (preserving total value)
6. Substitutes the redeemer ByteString with the other token's name
7. Checks that the modified transaction does NOT validate

== Precondition failure

If no swappable pair is found, the threat model calls 'failPrecondition' with
a message explaining what's needed. This results in the test being SKIPPED
(not failed) because the transaction doesn't have the structure needed to
test this particular vulnerability.

To satisfy the precondition, ensure the transaction has at least two different
tokens from the same policy in different outputs. See the module documentation
for strategies to achieve this in 'TestingInterface'.

== Example: Before and After

__Before swap:__

@
Output 0: 50 ADA + 1 (PolicyX, \"ValuableNFT\")    -- to contract owner
Output 1: 10 ADA + 1 (PolicyX, \"WorthlessJunk\")  -- change output
Redeemer: SellRedeemer { token_name: \"ValuableNFT\" }
@

__After swap:__

@
Output 0: 50 ADA + 1 (PolicyX, \"WorthlessJunk\")  -- swapped!
Output 1: 10 ADA + 1 (PolicyX, \"ValuableNFT\")    -- swapped!
Redeemer: SellRedeemer { token_name: \"WorthlessJunk\" }  -- substituted!
@

If the validator accepts this modified transaction, it is vulnerable because
it didn't verify that \"WorthlessJunk\" matches what the datum specified.

Usage:

@
threatPrecondition $ redeemerAssetSubstitution
@
-}
redeemerAssetSubstitution :: ThreatModel ()
redeemerAssetSubstitution = Named "Redeemer Asset Substitution" $ do
  -- Step 1: Find a script input (non-key address input)
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)

  -- Step 2: Get the redeemer for this script input
  redeemer <-
    getRedeemer scriptInput >>= \case
      Nothing -> failPrecondition "No redeemer found for script input"
      Just redeemer' -> pure redeemer'

  -- Step 3: Extract all ByteStrings from the redeemer (potential token names)
  let redeemerByteStrings = extractByteStrings redeemer

  -- Filter to valid token name candidates (non-empty, <= 32 bytes per Cardano spec)
  let validByteStrings = filter (\bs -> not (BS.null bs) && BS.length bs <= 32) redeemerByteStrings

  -- Fail precondition if no valid ByteStrings found in redeemer
  _ <- case validByteStrings of
    [] -> failPrecondition "No valid ByteStrings found in redeemer (empty or too long)"
    xs -> pure xs

  -- Step 4: Get all transaction outputs
  outputs <- getTxOutputs

  -- Step 5 & 6: Find a swappable pair
  -- For each redeemer ByteString, find:
  --   (a) An output containing token (policyP, originalName) where originalName matches the ByteString
  --   (b) A DIFFERENT output containing token (policyP, otherName) from the SAME policy
  let swappablePairs = findSwappablePairs validByteStrings outputs

  -- Pick the first valid swappable pair, or fail precondition
  (output1, output2, policyId, origAssetName, otherAssetName, origQty, otherQty, origBs) <-
    case listToMaybe swappablePairs of
      Nothing ->
        failPrecondition $
          "No swappable token pair found. The transaction needs at least two different "
            ++ "tokens from the same policy in different outputs. This naturally happens when "
            ++ "the wallet holds multiple tokens from the same policy and coin selection "
            ++ "includes them in the transaction."
      Just pair -> pure pair

  -- Step 7: Build the swapped values for both outputs
  -- Output1: remove originalName, add otherName
  -- Output2: remove otherName, add originalName
  let newValue1 = swapToken policyId origAssetName otherAssetName origQty otherQty (valueOf output1)
      newValue2 = swapToken policyId otherAssetName origAssetName otherQty origQty (valueOf output2)

  -- Step 8: Build the modified redeemer (substitute originalName with otherName)
  let C.UnsafeAssetName otherBs = otherAssetName
      modifiedRedeemer = substituteByteString origBs otherBs redeemer

  -- Log counterexample information for debugging
  counterexampleTM $
    paragraph
      [ "Testing Redeemer Asset Substitution vulnerability (swappable-pair approach):"
      , "Found two outputs with different tokens from the same policy."
      , "Swapping tokens between outputs and substituting redeemer."
      ]

  counterexampleTM $
    paragraph
      [ "Policy: " ++ show policyId
      , "Original token (from redeemer): " ++ show origAssetName
      , "Other token (for swap): " ++ show otherAssetName
      ]

  counterexampleTM $
    paragraph
      [ "Output 1 original value: " ++ show (valueOf output1)
      , "Output 1 new value: " ++ show newValue1
      , "Output 2 original value: " ++ show (valueOf output2)
      , "Output 2 new value: " ++ show newValue2
      ]

  counterexampleTM $
    paragraph
      [ "Original redeemer: " ++ show redeemer
      , "Modified redeemer: " ++ show modifiedRedeemer
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the validator trusts redeemer-provided"
      , "asset identifiers without cross-checking the datum."
      , "An attacker could substitute worthless tokens for valuable ones."
      ]

  -- Step 9 & 10: Compose modifications and check validation
  -- The modified transaction should NOT validate
  -- If it does validate, the contract is vulnerable
  shouldNotValidate $
    changeRedeemerOf scriptInput modifiedRedeemer
      <> changeValueOf output1 newValue1
      <> changeValueOf output2 newValue2

{- | Find all swappable pairs in the transaction.

Returns list of tuples:
(output1, output2, policyId, origAssetName, otherAssetName, origQty, otherQty, origBs)
-}
findSwappablePairs
  :: [BS.ByteString]
  -> [Output]
  -> [(Output, Output, C.PolicyId, C.AssetName, C.AssetName, C.Quantity, C.Quantity, BS.ByteString)]
findSwappablePairs validBs outputs = do
  -- For each valid ByteString from the redeemer
  bs <- validBs
  let targetAssetName = C.UnsafeAssetName bs

  -- Find output1: an output containing a token whose name matches the ByteString
  output1 <- outputs
  let out1Value = valueOf output1
      out1Assets = toList out1Value
  -- Find matching asset in output1
  (C.AssetId policyId assetName1, qty1) <- out1Assets
  guard (assetName1 == targetAssetName && qty1 > 0)

  -- Find output2: a DIFFERENT output with a DIFFERENT token from the SAME policy
  output2 <- outputs
  -- Must be different output (comparing by TxIx)
  guard (outputIx output1 /= outputIx output2)
  let out2Value = valueOf output2
  -- Find a different token from the same policy in output2
  case findDifferentTokenFromPolicy policyId assetName1 out2Value of
    Nothing -> []
    Just (assetName2, qty2) ->
      pure (output1, output2, policyId, assetName1, assetName2, qty1, qty2, bs)

-- | Find a token from the given policy with a different name than the excluded one.
findDifferentTokenFromPolicy
  :: C.PolicyId
  -> C.AssetName
  -- ^ Excluded asset name
  -> C.Value
  -> Maybe (C.AssetName, C.Quantity)
findDifferentTokenFromPolicy targetPolicy excludedName value =
  let assets = toList value
      candidates =
        [ (name, qty)
        | (C.AssetId policy name, qty) <- assets
        , policy == targetPolicy
        , name /= excludedName
        , qty > 0
        ]
   in listToMaybe candidates

{- | Swap a token in a Value: remove one asset and add another from the same policy.

Removes @(policy, removeAsset)@ with @removeQty@ and adds @(policy, addAsset)@ with @addQty@.
-}
swapToken
  :: C.PolicyId
  -> C.AssetName
  -- ^ Asset to remove
  -> C.AssetName
  -- ^ Asset to add
  -> C.Quantity
  -- ^ Quantity to remove
  -> C.Quantity
  -- ^ Quantity to add
  -> C.Value
  -> C.Value
swapToken policyId removeAsset addAsset removeQty addQty value =
  value
    <> C.negateValue (fromList [(C.AssetId policyId removeAsset, removeQty)])
    <> fromList [(C.AssetId policyId addAsset, addQty)]

{- | Extract all ByteStrings from a ScriptData structure.

Recursively traverses the ScriptData and returns all ByteString values found.
These are potential token names that the validator might be trusting from the redeemer.
-}
extractByteStrings :: C.ScriptData -> [BS.ByteString]
extractByteStrings = go
 where
  go :: C.ScriptData -> [BS.ByteString]
  go sd = case sd of
    C.ScriptDataBytes bs -> [bs]
    C.ScriptDataConstructor _ fields -> concatMap go fields
    C.ScriptDataList items -> concatMap go items
    C.ScriptDataMap pairs -> concatMap (\(k, v) -> go k ++ go v) pairs
    C.ScriptDataNumber _ -> []

{- | Substitute a specific ByteString with a new value in ScriptData.

Replaces ALL occurrences of the target ByteString with the replacement.
This is used to modify the redeemer to use the swapped token name.
-}
substituteByteString :: BS.ByteString -> BS.ByteString -> C.ScriptData -> C.ScriptData
substituteByteString target replacement = go
 where
  go :: C.ScriptData -> C.ScriptData
  go sd = case sd of
    C.ScriptDataBytes bs
      | bs == target -> C.ScriptDataBytes replacement
      | otherwise -> sd
    C.ScriptDataConstructor n fields ->
      C.ScriptDataConstructor n (map go fields)
    C.ScriptDataList items ->
      C.ScriptDataList (map go items)
    C.ScriptDataMap pairs ->
      C.ScriptDataMap [(go k, go v) | (k, v) <- pairs]
    C.ScriptDataNumber _ -> sd

-- | Guard helper for list comprehensions
guard :: Bool -> [()]
guard True = [()]
guard False = []
