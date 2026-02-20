use cardano/transaction.{OutputReference, Transaction}

/// Redeemer containing a message that must match the secret password
pub type Redeemer {
  msg: ByteArray,
}

/// Simple password validator from CTF challenges.
/// 
/// The UTxO can only be spent if the redeemer contains "Hello CTF!".
/// This is a trivial example demonstrating validator logic.
validator ctf_hello_world {
  spend(
    _datum: Option<Void>,
    redeemer: Redeemer,
    _own_ref: OutputReference,
    _self: Transaction,
  ) {
    redeemer.msg == "Hello CTF!"
  }

  else(_) {
    fail
  }
}
