use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{lovelace_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use ctf/bank_types.{AccountDatum}

/// Bank validator for bank_00.
/// Holds pooled funds. Checks that fund_difference matches account balance change.
///
/// VULNERABILITY: No check that balance can't go negative.
/// Withdrawing more than deposited is possible.
validator ctf_bank_00_bank(account_script_hash: ByteArray) {
  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    // Find own input (bank input)
    expect Some(bank_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })

    // Get our script hash
    expect Script(own_hash) = bank_input.output.address.payment_credential

    // Find bank output (continuation at same address)
    expect Some(bank_output) =
      list.find(
        self.outputs,
        fn(output) {
          when output.address.payment_credential is {
            Script(hash) -> hash == own_hash
            _ -> False
          }
        },
      )

    // Find account input (from account script)
    expect Some(account_input) =
      list.find(
        self.inputs,
        fn(input) {
          when input.output.address.payment_credential is {
            Script(hash) -> hash == account_script_hash
            _ -> False
          }
        },
      )

    // Find account output
    expect Some(account_output) =
      list.find(
        self.outputs,
        fn(output) {
          when output.address.payment_credential is {
            Script(hash) -> hash == account_script_hash
            _ -> False
          }
        },
      )

    // Parse account datums
    expect InlineDatum(account_input_datum_raw) = account_input.output.datum
    expect account_input_datum: AccountDatum = account_input_datum_raw

    expect InlineDatum(account_output_datum_raw) = account_output.datum
    expect account_output_datum: AccountDatum = account_output_datum_raw

    // Calculate fund difference (positive = deposit, negative = withdrawal)
    let bank_input_lovelace = lovelace_of(bank_input.output.value)
    let bank_output_lovelace = lovelace_of(bank_output.value)
    let fund_difference = bank_output_lovelace - bank_input_lovelace

    // Check: account balance change matches fund difference
    // VULNERABILITY: No check that account_output_datum.balance >= 0
    account_output_datum.balance == account_input_datum.balance + fund_difference
  }

  else(_) {
    fail
  }
}
