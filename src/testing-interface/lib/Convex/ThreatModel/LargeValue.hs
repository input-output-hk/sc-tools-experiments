{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Large Value Attack vulnerabilities.

A Large Value Attack exploits validators that don't properly validate the
structure of @Value@ in their outputs. If a validator allows spending from
a script output without checking what tokens are present in the output's value,
an attacker can "bloat" the value with additional junk tokens.

== Consequences ==

1. __Increased min-UTxO requirements__: Each unique token in a UTxO increases
   the minimum Ada required. Adding many junk tokens forces the victim to
   lock more Ada than intended.

2. __Serialization costs__: Large values increase transaction size, consuming
   more of the victim's fee budget when spending the UTxO.

3. __Permanent fund locking__: If the value is bloated sufficiently:

   - The transaction required to spend the UTxO may exceed protocol size limits
   - The serialized output may exceed the max-value-size protocol parameter

   In these cases, the UTxO becomes __permanently unspendable__ and funds
   are locked forever with no possibility of recovery.

== Root Cause ==

Validators that don't check the @Value@ structure of outputs being created.
For example, a validator that only checks:

@
traceIfFalse "insufficient payment" (valuePaidTo pkh >= expectedAmount)
@

This allows an attacker to include @expectedAmount + junkTokens@, satisfying
the check while bloating the output.

== Mitigation ==

A secure validator should either:

- Whitelist expected tokens (only allow known policy IDs)
- Check the token count (e.g., @length (flattenValue v) <= maxTokens@)
- Require exact value match (not just @>=@ comparison)
- Validate that outputs contain only expected assets

This threat model tests if a script output can have arbitrary tokens added
to its value via minting. If the transaction still validates, the validator
has a Large Value Attack vulnerability.
-}
module Convex.ThreatModel.LargeValue (
  largeValueAttack,
  largeValueAttackWith,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel
import Convex.ThreatModel.TxModifier (addPlutusScriptMint, alwaysSucceedsMintingPolicy)
import Data.ByteString.Char8 qualified as BS
import GHC.Exts (fromList)

{- | Check for Large Value Attack vulnerabilities with 50 junk tokens.

This is the default configuration that mints 50 unique tokens and adds them
to a script output. If the transaction still validates, the script doesn't
properly validate the value structure of its outputs.
-}
largeValueAttack :: ThreatModel ()
largeValueAttack = largeValueAttackWith 50

{- | Check for Large Value Attack vulnerabilities with a configurable number
of junk tokens.

For a transaction with script outputs:

* Mint @n@ unique junk tokens using an always-succeeds minting policy
* Add these tokens to a script output's value
* If the transaction still validates, the script doesn't validate
  the structure of values being created - it may only check amounts.

This catches a vulnerability where validators use permissive value checks
like @valuePaidTo addr >= expected@ instead of exact matching, allowing
attackers to inflate UTxO min-Ada requirements or lock funds permanently.
-}
largeValueAttackWith :: Int -> ThreatModel ()
largeValueAttackWith numTokens = Named ("Large Value Attack (" ++ show numTokens ++ " tokens)") $ do
  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs (NOT key addresses)
  let scriptOutputs = filter (not . isKeyAddressAny . addressOf) outputs

  -- Precondition: there must be at least one script output
  threatPrecondition $ ensure (not $ null scriptOutputs)

  -- Pick a target script output
  target <- pickAny scriptOutputs

  -- Create junk tokens by minting with the always-succeeds policy
  let policyId = C.PolicyId $ hashScript (C.PlutusScript C.PlutusScriptV2 alwaysSucceedsMintingPolicy)
      junkTokens =
        [ (C.UnsafeAssetName $ BS.pack $ "junk" ++ show i, C.Quantity 1)
        | i <- [1 .. numTokens]
        ]
      junkValue =
        fromList
          [ (C.AssetId policyId name, qty)
          | (name, qty) <- junkTokens
          ]
      bloatedValue = valueOf target <> junkValue

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if"
      , show numTokens
      , "junk tokens can be minted and added to the output's value"
      , "while still passing validation."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script's value validation is permissive."
      , "An attacker could exploit this to:"
      , "1) Increase min-UTxO requirements, locking victim's Ada"
      , "2) Inflate transaction sizes, increasing spending costs"
      , "3) Potentially lock funds permanently if size limits are exceeded"
      ]

  -- Create mint modifiers for all junk tokens
  let mintModifiers =
        mconcat
          [ addPlutusScriptMint alwaysSucceedsMintingPolicy name qty (toScriptData ())
          | (name, qty) <- junkTokens
          ]

  -- This SHOULD fail - if it validates, the contract is vulnerable
  -- The attack: mint junk tokens AND add them to the target output
  shouldNotValidate $
    changeValueOf target bloatedValue
      <> mintModifiers
