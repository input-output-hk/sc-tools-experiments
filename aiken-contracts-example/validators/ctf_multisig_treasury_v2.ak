use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address}
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

/// Datum for the enhanced multisig coordinator with validation token
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
  /// Use the multisig to release funds
  Use
}

/// Redeemer for the validation token minting policy
pub type ValidationMintRedeemer {
  /// Mint a new validation token (VULNERABLE)
  MintValidation
  /// Burn a validation token
  BurnValidation
}

/// Enhanced multisig treasury v2 with validation tokens.
///
/// This version requires a validation token to be present in the input
/// when using the multisig. The idea is that the token proves the
/// proposal was properly created and signed.
///
/// VULNERABILITY: The validation token minting policy allows ANYONE
/// to mint a new token if they can sign the transaction! There's no
/// check that a legitimate proposal exists or that all required
/// signers have approved.
///
/// Attack:
/// 1. Attacker mints a new validation token with MintValidation
/// 2. Places it at the multisig script with attacker as sole signed_user
/// 3. Uses the multisig immediately to drain treasury
validator ctf_multisig_treasury_v2 {
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
        list.any(
          datum.required_signers,
          fn(signer) { list.has(self.extra_signatories, signer) },
        )
      }

      Use -> {
        // Check that ANY signed_user has signed (still vulnerable like v1)
        // AND that a validation token is present in the mint (simulating token check)
        and {
          list.any(
            datum.signed_users,
            fn(sig) { list.has(self.extra_signatories, sig) },
          ),
          // The validation token check - but the token can be freely minted!
          has_any_minted_tokens(self),
        }
      }
    }
  }

  mint(redeemer: ValidationMintRedeemer, _policy_id: ByteArray, self: Transaction) {
    when redeemer is {
      MintValidation -> {
        // VULNERABILITY: Anyone who signs can mint!
        // Should check: Proposal was created by authorized parties
        // Should check: All required signers have approved
        // Actually checks: Just that someone signed the transaction
        list.length(self.extra_signatories) > 0
      }

      BurnValidation -> {
        // Burning is always allowed
        True
      }
    }
  }

  else(_) {
    fail
  }
}

/// Check if there are any minted tokens in the transaction
fn has_any_minted_tokens(self: Transaction) -> Bool {
  !dict.is_empty(assets.to_dict(self.mint))
}
