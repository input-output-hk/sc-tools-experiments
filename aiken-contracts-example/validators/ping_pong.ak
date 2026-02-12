use aiken/collection/list

use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}

/// State of the ping-pong contract
pub type State {
  Pinged
  Ponged
  Stopped
}

/// Actions that can be performed on the contract
pub type Action {
  Ping
  Pong
  Stop
}

/// Secure PingPong validator — Aiken implementation.
///
/// Checks:
/// 1. Valid state transitions (Pinged+Pong→Ponged, Ponged+Ping→Pinged, *+Stop→Stopped)
/// 2. Continuation output goes to the SAME script address (prevents output redirect)
/// 3. Output value equals input value (prevents large value attack)
validator ping_pong {
  spend(
    datum: Option<State>,
    redeemer: Action,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(current_state) = datum

    // Find our own input
    expect Some(own_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })

    let own_address = own_input.output.address
    let input_value = own_input.output.value

    // Find continuation output at our own address (SECURITY: prevents output redirect)
    expect Some(continuation) =
      list.find(
        self.outputs,
        fn(output) { output.address == own_address },
      )

    // SECURITY: Verify output value equals input value (prevents large value attack)
    expect continuation.value == input_value

    // Extract next state from continuation output
    expect InlineDatum(raw_next_state) = continuation.datum
    expect next_state: State = raw_next_state

    // Validate state transition
    when (current_state, redeemer, next_state) is {
      (Pinged, Pong, Ponged) -> True
      (Ponged, Ping, Pinged) -> True
      (Pinged, Stop, Stopped) -> True
      (Ponged, Stop, Stopped) -> True
      _ -> fail @"Invalid state transition"
    }
  }

  else(_) {
    fail
  }
}
