use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address}
use cardano/transaction.{OutputReference, Transaction}

/// Datum for the multisig coordinator
/// Tracks the intended release, beneficiary, required signers, and who has signed
pub type MultisigDatum {
  release_value: Int,
  beneficiary: Address,
  required_signers: List<VerificationKeyHash>,
  signed_users: List<VerificationKeyHash>,
}

/// Redeemer for the multisig validator
pub type MultisigRedeemer {
  /// Add a signature to the multisig
  Sign
  /// Use the multisig to release funds (VULNERABLE)
  Use
}

/// Simplified multisig treasury validator with intentional vulnerability.
///
/// VULNERABILITY: The `Use` action only checks that ANY ONE of the signed_users
/// has signed the transaction, rather than verifying ALL required_signers
/// have signed. This allows anyone who has ever signed to use the multisig,
/// even if the other required signers haven't approved.
///
/// Expected behavior: ALL required_signers must have signed (be in signed_users
/// AND sign the tx)
/// Actual behavior: ANY ONE signed_user signature is enough
validator ctf_multisig_treasury {
  spend(
    datum_opt: Option<MultisigDatum>,
    redeemer: MultisigRedeemer,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    when redeemer is {
      Sign -> {
        // Any required signer can add their signature
        // This should update the datum to add them to signed_users
        // For simplicity, we just check that a required signer is signing
        list.any(
          datum.required_signers,
          fn(signer) { list.has(self.extra_signatories, signer) },
        )
      }

      Use -> {
        // VULNERABILITY: Only checks that ONE signed_user has signed!
        // Should check: ALL required_signers are in signed_users AND have signed
        // Actually checks: ANY ONE of signed_users has signed the tx
        list.any(
          datum.signed_users,
          fn(sig) { list.has(self.extra_signatories, sig) },
        )
      }
    }
  }

  else(_) {
    fail
  }
}
