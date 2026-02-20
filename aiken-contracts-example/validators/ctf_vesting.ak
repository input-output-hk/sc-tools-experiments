use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Finite}
use cardano/transaction.{OutputReference, Transaction}

/// Datum for a vesting contract: locked until a certain time, for a specific beneficiary
pub type Datum {
  lock_until: Int,
  beneficiary: VerificationKeyHash,
}

/// Time-locked vesting validator with wrong time bound check.
///
/// VULNERABILITY: This validator checks the UPPER bound of the validity range
/// instead of the LOWER bound. The correct check should verify that the
/// transaction's validity range starts AFTER the lock_until time.
///
/// By checking upper_bound, an attacker can set a validity range like
/// [lock_until - 1000, lock_until + 1] and spend the UTxO early, as long
/// as the upper bound exceeds lock_until.
validator ctf_vesting {
  spend(
    datum_opt: Option<Datum>,
    _redeemer: Void,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    and {
      // Check beneficiary signed the transaction
      list.has(self.extra_signatories, datum.beneficiary)?,
      // VULNERABILITY: Checking upper_bound instead of lower_bound!
      time_elapsed(self, datum.lock_until)?,
    }
  }

  else(_) {
    fail
  }
}

/// Checks if the vesting period has elapsed.
/// VULNERABILITY: Uses upper_bound instead of lower_bound!
fn time_elapsed(tx: Transaction, vesting_lock_time: Int) -> Bool {
  when tx.validity_range.upper_bound.bound_type is {
    Finite(current_time) -> (vesting_lock_time <= current_time)?
    _ -> False
  }
}
