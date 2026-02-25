{- | Threat model for detecting signatory threshold vulnerabilities (1-of-N bugs).

A signatory threshold vulnerability occurs when a smart contract allows
transactions to succeed with fewer required signatories than expected.
This can happen when:

1. The validator uses @list.any@ instead of @list.all@ for checking signatures
2. The validator only checks that ONE of the required signers signed, not ALL
3. The multi-signature threshold logic is incorrectly implemented

== Consequences ==

1. __Unauthorized fund extraction__: An attacker who is one of N required
   signers can unilaterally withdraw funds that should require N-of-N approval.

2. __Governance bypass__: Multi-signature governance schemes become ineffective
   when a single party can act alone.

3. __Trust assumption violation__: Users who deposited funds expecting N-of-N
   security only get 1-of-N security.

== Vulnerable Pattern ==

@
-- Aiken example: Checks ANY signer instead of ALL
validator spend(..., datum, _redeemer, _ctx) {
  list.any(datum.required_signers, fn(signer) {
    list.has(ctx.transaction.extra_signatories, signer)
  })
}
@

Should be:

@
-- Correct: Checks ALL signers
validator spend(..., datum, _redeemer, _ctx) {
  list.all(datum.required_signers, fn(signer) {
    list.has(ctx.transaction.extra_signatories, signer)
  })
}
@

== Mitigation ==

A secure multi-signature validator should:

- Check that ALL required signers have signed (use @list.all@, not @list.any@)
- Verify the exact threshold (e.g., 2-of-3, 3-of-5) is met
- Use a proper multi-sig scheme with explicit threshold parameter

This threat model tests if a transaction with multiple required signers
still validates when required signatories are removed one at a time.
-}
module Convex.ThreatModel.SignatoryRemoval (
  signatoryRemoval,
) where

import Convex.ThreatModel (
  ThreatModel,
  failPrecondition,
  getTxRequiredSigners,
  pickAny,
  shouldNotValidate,
  threatPrecondition,
 )
import Convex.ThreatModel.TxModifier (removeRequiredSigner)

{- | Generic threat model: remove required signatories one at a time.

For a transaction with multiple required signers, this threat model:

1. Gets all required signers from the transaction body
2. Picks one signer at random
3. Removes that signer from the required signers list
4. Checks that the transaction should NOT validate

If the transaction still validates with fewer signers, the contract
has a threshold vulnerability (e.g., 1-of-N instead of N-of-N).

This is a property-based approach - QuickCheck will run this multiple
times with different random signers being removed, exploring the space
of possible single-signer removals.

Note: This threat model requires at least one required signer in the
transaction. Transactions with no required signers will be skipped.
-}
signatoryRemoval :: ThreatModel ()
signatoryRemoval = do
  signers <- getTxRequiredSigners
  -- Precondition: there must be at least one required signer to remove
  threatPrecondition $ do
    case signers of
      [] -> failPrecondition "No required signers in transaction"
      _ -> pure ()
  -- Pick a random signer to remove
  signer <- pickAny signers
  -- The transaction should NOT validate with this signer removed
  shouldNotValidate (removeRequiredSigner signer)
