{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Time Bound Manipulation vulnerabilities.

A Time Bound Manipulation vulnerability occurs when a validator checks the wrong
bound of a transaction's validity range. The most common case is a vesting
contract that should check the lower bound but mistakenly checks the upper bound.

== The Vulnerability ==

Consider a vesting contract that should enforce: "funds can only be withdrawn
after timestamp T". A correct implementation checks:

@
let must_be_after = range.lower_bound >= lock_until
@

But a vulnerable implementation might check:

@
let must_be_after = range.upper_bound >= lock_until  -- WRONG!
@

The difference:

* __Lower bound check__: The transaction can only be submitted when the current
  slot time >= lower_bound. If lower_bound >= deadline, the transaction truly
  cannot be submitted before the deadline.

* __Upper bound check__: Only requires that the validity range EXTENDS past the
  deadline. A transaction valid in range [0, deadline+1] would pass the check
  even though it could be submitted at time 0!

== Consequences ==

An attacker can withdraw vested funds before the vesting period ends by
constructing a transaction with:

* Current time: before the deadline (e.g., slot 0)
* Validity range: [0, deadline + margin]

The upper bound extends past the deadline, so the script passes, but the
transaction is actually submitted BEFORE the deadline.

== Root Cause ==

The script author confused what validity bounds mean. The validity range
[lower, upper] means "this transaction is valid if the current slot is
in this range". To ensure "not before time T", you must check lower_bound >= T.

== Mitigation ==

Always check the LOWER bound when enforcing "not before" conditions:

@
fn time_elapsed(range, deadline) {
  when range.lower_bound.bound_type is {
    Finite(current_time) -> deadline <= current_time
    _ -> False
  }
}
@

This threat model tests by taking a valid transaction and widening its lower
bound to slot 0. If the script still validates, it doesn't properly check
that the transaction cannot be submitted early.
-}
module Convex.ThreatModel.TimeBoundManipulation (
  timeBoundManipulation,
  timeBoundManipulationWith,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel

{- | Check for time bound manipulation vulnerabilities.

Takes a valid transaction (presumably one that passed a time check with a proper
validity range like [deadline, deadline+margin]) and widens the lower bound to
slot 0.

If the transaction still validates, the script only checks the upper bound,
not the lower bound. This means the transaction could actually be submitted
at any time from slot 0 to the upper bound, defeating the time restriction.

A properly implemented time check would FAIL when we widen the lower bound
because it would detect that the transaction could be submitted before the deadline.
-}
timeBoundManipulation :: ThreatModel ()
timeBoundManipulation = timeBoundManipulationWith (SlotNo 0)

{- | Check for time bound manipulation with a configurable lower bound.

@timeBoundManipulationWith (SlotNo 0)@ is the standard attack:
Widen the validity range to start from slot 0.

You can also use a specific slot to test if the script would accept
a transaction valid at that earlier time.
-}
timeBoundManipulationWith :: SlotNo -> ThreatModel ()
timeBoundManipulationWith earlySlot@(C.SlotNo slotNum) = Named ("Time Bound Manipulation (slot " ++ show slotNum ++ ")") $ do
  counterexampleTM $
    paragraph
      [ "Testing for Time Bound Manipulation vulnerability."
      , "A correct time-lock validator should check the LOWER bound of the validity range,"
      , "ensuring the transaction cannot be submitted before the deadline."
      ]

  counterexampleTM $
    paragraph
      [ "We widen the validity range's lower bound to slot"
      , show slotNum
      , "."
      , "If the script still validates, it likely checks upper_bound instead of lower_bound."
      ]

  counterexampleTM $
    paragraph
      [ "The original transaction had a validity range that starts at or after the deadline."
      , "By widening the lower bound, we make it possible to submit the transaction early."
      , "A secure validator would REJECT this because the lower bound is too early."
      ]

  -- The attack: widen the lower bound to an early slot
  -- If the script checks lower_bound >= deadline, this should FAIL
  -- If the script only checks upper_bound >= deadline, this will PASS (vulnerability!)
  shouldNotValidate $
    changeValidityLowerBound (C.TxValidityLowerBound C.allegraBasedEra earlySlot)
