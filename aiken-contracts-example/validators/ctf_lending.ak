use aiken/collection/list
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{lovelace_of}
use cardano/transaction.{Input, OutputReference, Transaction}

/// Datum for a P2P lending contract
pub type LendingDatum {
  borrower: Address,
  lender: Option<Address>,
  borrowed_amount: Int,
  interest: Int,
  loan_duration: Int,
  loan_end: Option<Int>,
  collateral_policy: ByteArray,
  repaid: Bool,
}

/// Actions for the lending contract
pub type LendingRedeemer {
  /// Borrower requests a loan by locking collateral
  RequestLoan
  /// Lender provides funds to the borrower
  Lend
  /// Borrower repays the loan with interest
  Repay
}

/// P2P Lending validator with first-input bypass vulnerability.
///
/// VULNERABILITY: In the `Lend` handler, there's an OR condition that checks:
///   own_ref != first_script_input_ref OR loans_paid_to_borrowers(...)
///
/// This means if a transaction spends multiple lending UTxOs, only the FIRST
/// one actually verifies that funds are paid to borrowers. All subsequent
/// inputs bypass the payment check entirely!
///
/// Attack: Spend multiple loan requests in one tx. Pay borrower for first loan,
/// but steal the rest by not paying the other borrowers.
validator ctf_lending {
  spend(
    datum_opt: Option<LendingDatum>,
    redeemer: LendingRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Find our own input
    expect Some(own_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })

    // Get our script hash
    expect Script(own_hash) = own_input.output.address.payment_credential

    when redeemer is {
      RequestLoan -> {
        // Borrower creates a loan request by locking collateral
        // For simplicity, just check borrower signed
        has_signed(self, datum.borrower)
      }

      Lend -> {
        // VULNERABILITY: First-input bypass!
        // Find the first script input from this contract
        let first_script_input_ref = get_first_script_input_ref(self.inputs)

        // The vulnerable OR condition:
        // If this is NOT the first script input, we skip the payment check!
        or {
          own_ref != first_script_input_ref,
          loans_paid_to_borrowers(self, own_hash, datum.borrowed_amount),
        }
      }

      Repay -> {
        // Borrower repays loan + interest
        // Check that lender receives the repayment
        expect Some(lender_addr) = datum.lender
        let required_repayment = datum.borrowed_amount + datum.interest
        paid_to_address(self, lender_addr, required_repayment)
      }
    }
  }

  else(_) {
    fail
  }
}

/// Get the output reference of the first script input
fn get_first_script_input_ref(inputs: List<Input>) -> OutputReference {
  expect Some(first_script_input) =
    list.find(
      inputs,
      fn(input) {
        when input.output.address.payment_credential is {
          Script(_) -> True
          _ -> False
        }
      },
    )
  first_script_input.output_reference
}

/// Check if address has signed (for pubkey addresses)
fn has_signed(self: Transaction, addr: Address) -> Bool {
  when addr.payment_credential is {
    VerificationKey(vkh) -> list.has(self.extra_signatories, vkh)
    _ -> False
  }
}

/// Check if the borrower was paid the borrowed amount
/// This only checks first loan for simplicity
fn loans_paid_to_borrowers(
  self: Transaction,
  _own_hash: ByteArray,
  borrowed_amount: Int,
) -> Bool {
  // For simplicity, check that any output has at least borrowed_amount lovelace
  list.any(
    self.outputs,
    fn(output) { lovelace_of(output.value) >= borrowed_amount },
  )
}

/// Check if a specific address received at least the required amount
fn paid_to_address(self: Transaction, addr: Address, amount: Int) -> Bool {
  list.any(
    self.outputs,
    fn(output) {
      output.address == addr && lovelace_of(output.value) >= amount
    },
  )
}
