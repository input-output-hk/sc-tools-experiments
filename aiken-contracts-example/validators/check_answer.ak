use cardano/transaction.{OutputReference, Transaction}

/// A simple spending validator that checks: datum + redeemer == 43
///
/// - datum: An integer stored as inline datum at the UTxO
/// - redeemer: An integer provided when spending
///
/// This demonstrates that Aiken-compiled validators work with
/// the sc-tools testing-interface framework.
validator check_answer {
  spend(
    datum: Option<Int>,
    redeemer: Int,
    _own_ref: OutputReference,
    _self: Transaction,
  ) {
    expect Some(stored_number) = datum
    stored_number + redeemer == 43
  }

  else(_) {
    fail
  }
}
