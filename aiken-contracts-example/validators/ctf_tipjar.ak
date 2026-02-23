use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Script}
use cardano/assets.{lovelace_of}
use cardano/transaction.{InlineDatum, Input, OutputReference, Transaction, find_script_outputs}

/// The datum stored at the tipjar script address
pub type Datum {
  owner: VerificationKeyHash,
  messages: List<ByteArray>,
}

/// Actions: tip into the jar, or owner claims it
pub type Redeemer {
  Claim
  AddTip
}

const minimum_tip: Int = 5_000_000

validator ctf_tipjar {
  spend(
    datum_opt: Option<Datum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Find our own input
    expect Some(own_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })

    // Get our script hash
    expect Script(own_hash) = own_input.output.address.payment_credential

    // Only 1 script input allowed
    expect count_input_scripts(self.inputs) == 1

    when redeemer is {
      AddTip -> {
        // Find script outputs going back to our address
        let script_outputs = find_script_outputs(self.outputs, own_hash)

        // Only 1 script output allowed for AddTip
        expect list.length(script_outputs) == 1
        expect Some(script_output) = list.head(script_outputs)

        // Parse the output datum
        expect InlineDatum(output_datum_raw) = script_output.datum
        expect output_datum: Datum = output_datum_raw

        and {
          // Value must increase by at least minimum_tip
          (lovelace_of(own_input.output.value) + minimum_tip <= lovelace_of(
            script_output.value,
          ))?,
          // Datum must be correctly updated
          datum_is_correct(datum, output_datum)?,
        }
      }
      // Owner can claim the tip jar by signing the transaction
      // No continuation output required - owner takes all funds
      Claim -> list.has(self.extra_signatories, datum.owner)
    }
  }

  else(_) {
    fail
  }
}

fn count_input_scripts(inputs: List<Input>) -> Int {
  list.count(
    inputs,
    fn(input) {
      when input.output.address.payment_credential is {
        Script(_) -> True
        _ -> False
      }
    },
  )
}

fn datum_is_correct(input_datum: Datum, output_datum: Datum) -> Bool {
  and {
    // Check that the owner is not changed
    (input_datum.owner == output_datum.owner)?,
    // Check that no messages were changed and one new is added
    datum_contains_one_more_message(input_datum.messages, output_datum.messages)?,
  }
}

/// VULNERABILITY: No limit on ByteArray size! An attacker can add a huge message,
/// bloating the datum beyond transaction size limits and causing permanent DoS.
fn datum_contains_one_more_message(
  input_messages: List<ByteArray>,
  output_messages: List<ByteArray>,
) -> Bool {
  let new_message = list.head(output_messages)
  when new_message is {
    Some(msg) -> list.push(input_messages, msg) == output_messages
    None -> False
  }
}
