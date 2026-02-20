use aiken/collection/list
use cardano/address.{Address}
use cardano/assets.{lovelace_of}
use cardano/transaction.{OutputReference, Transaction}

/// Datum for an NFT listing: seller address and price in lovelace
pub type Datum {
  seller: Address,
  price: Int,
}

/// NFT marketplace validator with double satisfaction vulnerability.
///
/// VULNERABILITY: This validator only checks that "some output pays the seller
/// the required price". If multiple UTxOs from the same script are spent in
/// a single transaction, a single output can satisfy multiple inputs.
/// 
/// Example attack: If two NFTs are listed at 10 ADA each, an attacker can
/// spend both with only one 10 ADA payment to each seller (if same seller,
/// just 10 ADA total instead of 20 ADA).
validator ctf_sell_nft {
  spend(
    datum_opt: Option<Datum>,
    _redeemer: Void,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum_opt

    // Check that some output pays the seller at least the price
    // VULNERABILITY: No uniqueness check!
    expect
      Some(_) =
        list.find(
          self.outputs,
          fn(output) {
            and {
              (output.address == datum.seller)?,
              (lovelace_of(output.value) >= datum.price)?,
            }
          },
        )

    True
  }

  else(_) {
    fail
  }
}
