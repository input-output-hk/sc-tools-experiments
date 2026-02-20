use aiken/collection/list
use cardano/transaction.{OutputReference, Transaction}
use ctf/bank_types.{AccountDatum, AccountRedeemer, DecreaseBalance, IncreaseBalance}

/// Account validator for bank_01.
/// Same as bank_00 account - per-user account that authorizes balance changes.
///
/// - IncreaseBalance: always succeeds (anyone can deposit)
/// - DecreaseBalance: requires owner signature
validator ctf_bank_01_account {
  spend(
    datum_opt: Option<AccountDatum>,
    redeemer: AccountRedeemer,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    when redeemer is {
      // Anyone can increase balance (deposit)
      IncreaseBalance -> True
      // Only owner can decrease balance (withdrawal)
      DecreaseBalance -> list.has(self.extra_signatories, datum.owner)
    }
  }

  else(_) {
    fail
  }
}
