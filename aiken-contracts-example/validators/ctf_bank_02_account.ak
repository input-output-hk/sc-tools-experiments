use aiken/collection/list
use cardano/address.{Script}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use ctf/bank_types.{AccountDatum, AccountRedeemer, DecreaseBalance, IncreaseBalance}

/// Account validator for bank_02.
/// Adds check: must find output with same owner.
///
/// VULNERABILITY: Multiple accounts in same tx can match each other's outputs.
/// Alice's account input can match Bob's account output if both have valid outputs.
validator ctf_bank_02_account {
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

    // Find output with same owner (VULNERABILITY: doesn't ensure it's OUR output)
    expect Some(_account_output) =
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

    // We found an output with same owner, now check redeemer
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
