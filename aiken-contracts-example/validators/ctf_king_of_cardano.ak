use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/assets.{lovelace_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction, find_script_outputs}

/// Datum for the king of cardano competition
pub type Datum {
  /// Current king's address (receives payment when overthrown)
  current_king: Address,
  /// Whether the competition is closed
  competition_closed: Bool,
}

/// Actions that can be performed
pub type Redeemer {
  /// Pay more than current amount to become the new king
  OverthrowKing
  /// Close the competition (only current king can do this)
  CloseCompetition
}

/// King of Cardano competition validator with intentional vulnerability.
///
/// VULNERABILITY: Self-reference attack. If current_king is set to the
/// script address itself, the "payment to previous king" goes back to
/// the script. This makes overthrows essentially free since the attacker
/// doesn't actually lose any funds - they just cycle them through the script.
///
/// Attack flow:
/// 1. Become king normally with X Ada
/// 2. Set current_king to the script's own address
/// 3. Future challengers pay to the script, not to you
/// 4. You can keep reclaiming as "king" without real cost
validator ctf_king_of_cardano {
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
    let input_value = lovelace_of(own_input.output.value)

    when redeemer is {
      OverthrowKing -> {
        // Competition must be open
        expect !datum.competition_closed

        // Find continuation output at script address
        let script_outputs = find_script_outputs(self.outputs, own_hash)
        expect list.length(script_outputs) == 1
        expect Some(continuation) = list.head(script_outputs)

        let output_value = lovelace_of(continuation.value)

        // Parse continuation datum
        expect InlineDatum(raw_next_datum) = continuation.datum
        expect next_datum: Datum = raw_next_datum

        // Check that current king receives at least the input value
        // VULNERABILITY: If current_king == own_address, this payment
        // goes back to the script, making the overthrow essentially free!
        let king_paid =
          list.any(
            self.outputs,
            fn(output) {
              and {
                output.address == datum.current_king,
                lovelace_of(output.value) >= input_value,
              }
            },
          )

        and {
          // New value must be greater than old value
          (output_value > input_value)?,
          // Current king must be paid
          king_paid?,
          // Competition must remain open
          (!next_datum.competition_closed)?,
        }
      }

      CloseCompetition -> {
        // For simplicity, anyone can close if they sign
        // In the real CTF, only the king can close
        // This just checks that the datum is updated correctly
        let script_outputs = find_script_outputs(self.outputs, own_hash)
        expect list.length(script_outputs) == 1
        expect Some(continuation) = list.head(script_outputs)

        expect InlineDatum(raw_next_datum) = continuation.datum
        expect next_datum: Datum = raw_next_datum

        // Just verify the competition is now closed
        next_datum.competition_closed
      }
    }
  }

  else(_) {
    fail
  }
}
