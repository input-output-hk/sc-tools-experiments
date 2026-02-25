{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Threat model for detecting Value Underpayment vulnerabilities.

A Value Underpayment Attack exploits validators that don't properly verify
that the actual ADA value in an output matches the expected value based on
the datum. If a validator tracks a "balance" in the datum but doesn't verify
the actual ADA matches, an attacker can modify transactions to underpay.

== Example Vulnerability ==

Consider a bank contract where the account datum tracks a balance:

@
data AccountDatum = AccountDatum { balance :: Integer, owner :: PubKeyHash }
@

If the deposit action (IncreaseBalance) only checks that:
- The output datum has an increased balance
- But doesn't verify that the actual ADA value increased by the same amount

Then an attacker can "deposit" by increasing the datum balance without
adding any actual ADA to the output.

== Consequences ==

1. __Free balance increases__: Attacker gains balance without depositing funds
2. __Theft of pooled funds__: If the bank pays out based on datum balance,
   the attacker can withdraw more than they deposited
3. __Insolvency__: Multiple attackers can drain the bank's pooled funds

== Root Cause ==

Validators that:
- Track value in datum without verifying actual UTxO value matches
- Only check datum changes without checking corresponding value changes
- Allow balance increases without requiring matching fund increases

== Mitigation ==

A secure validator should:
- Verify output value matches expected value based on datum
- Check that fund_difference == balance_change for deposits/withdrawals
- Never rely solely on datum for balance tracking

This threat model tests if a script output can have its ADA value reduced
while keeping the datum unchanged. If the transaction still validates,
the validator has a Value Underpayment vulnerability.
-}
module Convex.ThreatModel.ValueUnderpayment (
  valueUnderpaymentAttack,
  valueUnderpaymentAttackWith,
) where

import Cardano.Api qualified as C
import Convex.ThreatModel

-- | Minimum ADA to leave in the output (to avoid min-UTxO violations)
minOutputAda :: C.Lovelace
minOutputAda = 2_000_000

{- | Check for Value Underpayment vulnerabilities by halving the ADA value.

This is the default configuration that reduces the ADA in a script output
by 50%. If the transaction still validates, the script doesn't properly
verify that output values match expected amounts.
-}
valueUnderpaymentAttack :: ThreatModel ()
valueUnderpaymentAttack = valueUnderpaymentAttackWith 0.5

{- | Check for Value Underpayment vulnerabilities with a configurable
reduction factor.

For a transaction with script outputs:

* Find a script output with ADA value
* Reduce its ADA value by the given factor (e.g., 0.5 = halve it)
* Keep the datum unchanged
* If the transaction still validates, the script doesn't verify
  that output value matches the expected amount based on datum.

@reductionFactor@ should be between 0 and 1:
- 0.5 means reduce to 50% of original value
- 0.25 means reduce to 25% of original value
- 0.9 means reduce to 10% of original value (keep only 10%)

The attack ensures at least 'minOutputAda' remains to avoid min-UTxO failures.
-}
valueUnderpaymentAttackWith :: Double -> ThreatModel ()
valueUnderpaymentAttackWith reductionFactor = do
  -- Get all outputs from the transaction
  outputs <- getTxOutputs

  -- Filter to script outputs (NOT key addresses)
  let scriptOutputs = filter (not . isKeyAddressAny . addressOf) outputs

  -- Precondition: there must be at least one script output
  threatPrecondition $ ensure (not $ null scriptOutputs)

  -- Further filter to outputs that have enough ADA to be reduced
  let hasEnoughAda out =
        let adaValue = C.selectLovelace (valueOf out)
         in adaValue > minOutputAda
      reducibleOutputs = filter hasEnoughAda scriptOutputs

  -- Precondition: there must be at least one script output with enough ADA
  threatPrecondition $ ensure (not $ null reducibleOutputs)

  -- Pick a target script output
  target <- pickAny reducibleOutputs

  -- Calculate reduced value
  let currentValue = valueOf target
      currentAda = C.selectLovelace currentValue
      -- Calculate reduced ADA, ensuring we don't go below minimum
      -- Lovelace has a Num instance, so we can use numeric operations
      reducedAda = max minOutputAda (fromInteger $ round (fromIntegral currentAda * (1 - reductionFactor)))
      adaDifference = C.negateValue $ C.lovelaceToValue (currentAda - reducedAda)
      reducedValue = currentValue <> adaDifference

  counterexampleTM $
    paragraph
      [ "The transaction contains a script output at index"
      , show (outputIx target)
      , "."
      ]

  counterexampleTM $
    paragraph
      [ "Testing if the ADA value can be reduced from"
      , show currentAda
      , "to"
      , show reducedAda
      , "(reduction factor:"
      , show (reductionFactor * 100) ++ "%)"
      , "while keeping the datum unchanged."
      ]

  counterexampleTM $
    paragraph
      [ "If this validates, the script's value validation is insufficient."
      , "An attacker could exploit this to:"
      , "1) Increase their balance without depositing matching funds"
      , "2) Steal funds from pooled reserves"
      , "3) Create inconsistency between datum balance and actual UTxO value"
      ]

  -- This SHOULD fail - if it validates, the contract is vulnerable
  -- The attack: reduce the ADA value but keep datum the same
  shouldNotValidate $ changeValueOf target reducedValue
