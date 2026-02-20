use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{lovelace_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use ctf/bank_types.{AccountDatum}

/// Bank validator for bank_01.
/// Same as bank_00 but adds: account_output.balance >= 0
///
/// VULNERABILITY: Deposit doesn't verify actual funds sent to bank.
/// User could set balance to 1000 while only sending 1 lovelace.
validator ctf_bank_01_bank(account_script_hash: ByteArray) {
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
    // AND balance must be non-negative (fix for bank_00 vulnerability)
    and {
      account_output_datum.balance == account_input_datum.balance + fund_difference,
      account_output_datum.balance >= 0,
    }
  }

  else(_) {
    fail
  }
}
