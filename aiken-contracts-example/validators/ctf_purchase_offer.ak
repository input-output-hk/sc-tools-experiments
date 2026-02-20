use aiken/collection/list
use cardano/address.{Address}
use cardano/assets.{PolicyId, AssetName, quantity_of}
use cardano/transaction.{OutputReference, Transaction}

/// Datum for the purchase offer
/// Represents an offer to buy an NFT with a specific policy ID
pub type Datum {
  /// Owner who will receive the NFT
  owner: Address,
  /// The policy ID of the desired NFT
  desired_policy_id: PolicyId,
  /// Optional specific token name; if None, any token from the policy is accepted
  desired_token_name: Option<AssetName>,
}

/// Redeemer that specifies which token is being sold
pub type SellRedeemer {
  /// The policy ID of the token being sold
  sold_policy_id: PolicyId,
  /// The token name of the token being sold
  sold_token_name: AssetName,
}

/// Purchase offer validator with intentional vulnerability.
///
/// VULNERABILITY: When desired_token_name is None, the attacker controls
/// which token name satisfies the purchase via the redeemer. They can:
/// 1. Create a minting policy that matches the desired_policy_id
/// 2. Mint a worthless token with any name under that policy
/// 3. Sell that worthless token to claim the locked funds
///
/// This works because the validator trusts the redeemer-provided token name
/// without verifying it's a valuable/legitimate token.
validator ctf_purchase_offer {
  spend(
    datum_opt: Option<Datum>,
    redeemer: SellRedeemer,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Check that the sold asset matches the desired policy
    let policy_matches = redeemer.sold_policy_id == datum.desired_policy_id

    // Check token name if specified
    let token_name_matches =
      when datum.desired_token_name is {
        Some(required_name) -> redeemer.sold_token_name == required_name
        // VULNERABILITY: When None, ANY token name from the policy is accepted!
        // The attacker can mint a worthless token with the same policy ID
        None -> True
      }

    // Check that some output pays the owner with the sold asset
    let owner_receives_asset =
      list.any(
        self.outputs,
        fn(output) {
          and {
            output.address == datum.owner,
            quantity_of(
              output.value,
              redeemer.sold_policy_id,
              redeemer.sold_token_name,
            ) >= 1,
          }
        },
      )

    and {
      policy_matches?,
      token_name_matches?,
      owner_receives_asset?,
    }
  }

  else(_) {
    fail
  }
}
