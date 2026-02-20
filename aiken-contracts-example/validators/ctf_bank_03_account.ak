use aiken/collection/list
use cardano/address.{Script}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use ctf/bank_types.{AccountDatum, AccountRedeemer, DecreaseBalance, IncreaseBalance}

/// Account validator for bank_03.
/// Adds balance direction checks:
/// - IncreaseBalance: requires output balance > input balance
/// - DecreaseBalance: requires output balance < input balance AND owner signature
///
/// VULNERABILITY: Bank doesn't verify which account output corresponds to which input.
/// With multiple accounts in the same transaction, balances can be shuffled.
validator ctf_bank_03_account {
  spend(
    datum_opt: Option<AccountDatum>,
    redeemer: AccountRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Find own input
    expect Some(own_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })

    // Get our script hash
    expect Script(own_hash) = own_input.output.address.payment_credential

    // Find output with same owner
    expect Some(account_output) =
      list.find(
        self.outputs,
        fn(output) {
          when output.address.payment_credential is {
            Script(hash) ->
              if hash == own_hash {
                expect InlineDatum(out_datum_raw) = output.datum
                expect out_datum: AccountDatum = out_datum_raw
                out_datum.owner == datum.owner
              } else {
                False
              }
            _ -> False
          }
        },
      )

    // Parse output datum
    expect InlineDatum(account_output_datum_raw) = account_output.datum
    expect account_output_datum: AccountDatum = account_output_datum_raw

    when redeemer is {
      // Deposit: balance must increase
      IncreaseBalance -> account_output_datum.balance > datum.balance
      // Withdrawal: balance must decrease AND requires owner signature
      DecreaseBalance ->
        and {
          account_output_datum.balance < datum.balance,
          list.has(self.extra_signatories, datum.owner),
        }
    }
  }

  else(_) {
    fail
  }
}
