use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address, Script}
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
  /// Use the multisig to release funds (now requires burning validation token)
  Use
}

/// Redeemer for the validation token minting policy
pub type ValidationMintRedeemer {
  /// Mint a new validation token
  MintValidation
  /// Burn a validation token (required for Use)
  BurnValidation
}

/// Enhanced multisig treasury v3 with token burning requirement.
///
/// This version attempts to fix v2 by requiring the validation token
/// to be BURNED when using the multisig. The idea is that tokens
/// can only be used once.
///
/// VULNERABILITY: The `Sign` action doesn't properly validate signatures!
/// It only checks that the signer is in required_signers, but doesn't
/// prevent the same signer from signing multiple times. An attacker
/// can submit multiple Sign transactions to fill all signature slots
/// with their own key.
///
/// Attack:
/// 1. Create a proposal with attacker as one of required_signers
/// 2. Submit Sign tx multiple times (each time adds to signed_users)
/// 3. The datum ends up with attacker's key multiple times
/// 4. Mint validation token and Use to drain treasury
validator ctf_multisig_treasury_v3 {
  spend(
    datum_opt: Option<MultisigDatum>,
    redeemer: MultisigRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Find our own input for getting policy_id
    expect Some(own_input) =
      list.find(self.inputs, fn(input) { input.output_reference == own_ref })
    expect Script(own_hash) = own_input.output.address.payment_credential

    when redeemer is {
      Sign -> {
        // VULNERABILITY: Only checks signer is in required_signers
        // Does NOT check if they've already signed!
        // Allows same person to sign multiple times
        list.any(
          datum.required_signers,
          fn(signer) { list.has(self.extra_signatories, signer) },
        )
      }

      Use -> {
        // Fixed: Now requires burning the validation token
        let validation_token_policy = own_hash
        let expected_token_name = "validation"

        // Must burn exactly one validation token
        let token_pairs =
          self.mint
            |> assets.tokens(validation_token_policy)
            |> dict.to_pairs()

        expect [Pair(asset_name, amount)] = token_pairs

        and {
          // Check signed_user signed (still has the length issue from Sign)
          list.any(
            datum.signed_users,
            fn(sig) { list.has(self.extra_signatories, sig) },
          ),
          // Must burn the validation token (amount should be -1)
          asset_name == expected_token_name,
          amount == -1,
        }
      }
    }
  }

  mint(redeemer: ValidationMintRedeemer, _policy_id: ByteArray, self: Transaction) {
    when redeemer is {
      MintValidation -> {
        // Still allows minting if someone signs
        // But now tokens must be burned to use, so harder to exploit
        list.length(self.extra_signatories) > 0
      }

      BurnValidation -> {
        // Burning is always allowed - needed for Use action
        True
      }
    }
  }

  else(_) {
    fail
  }
}
