/// Shared types for the CTF bank series validators

/// The datum stored at an account script address
pub type AccountDatum {
  balance: Int,
  owner: ByteArray,
}

/// Actions that can be performed on an account
pub type AccountRedeemer {
  IncreaseBalance
  DecreaseBalance
}
