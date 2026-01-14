{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Vulnerable Bounty validator for threat model demonstration.

This validator is INTENTIONALLY VULNERABLE to double satisfaction attacks.
It only checks that "some output pays to the beneficiary" without uniquely
identifying which output belongs to this specific spend.

VULNERABILITY: An attacker can bundle multiple Bounty spends into a single
transaction where ONE output satisfies ALL of them, stealing the extra funds.

Use this module to demonstrate how the DoubleSatisfaction threat model
detects this vulnerability class.

See 'Scripts.Bounty' for the secure version.
-}
module Scripts.Bounty.Vulnerable.DoubleSatisfaction (
  validator,
  -- Re-export types from secure version for compatibility
  BountyDatum (..),
  BountyRedeemer (..),
) where

import PlutusLedgerApi.V1.Address (toPubKeyHash)
import PlutusLedgerApi.V1.Crypto (PubKeyHash)
import PlutusLedgerApi.V1.Scripts (Datum (getDatum))
import PlutusLedgerApi.V2.Tx (TxOut (..))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  ScriptInfo (SpendingScript),
  TxInfo (..),
 )
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P

-- Re-use types from the secure version
import Scripts.Bounty (BountyDatum (..), BountyRedeemer (..))

{- | VULNERABLE VALIDATOR

This validator ONLY checks that some output pays to the beneficiary.
It does NOT verify that the output is uniquely tied to this spend.

An attacker can:
1. Create multiple Bounty UTxOs paying to the same beneficiary
2. Spend them all in one transaction with a SINGLE output to the beneficiary
3. All validators pass because they each see "an output to beneficiary"
4. The attacker steals (n-1) * bountyAmount by only paying once

The secure version prevents this by requiring each output to contain
an inline datum with the specific TxOutRef being spent.
-}
{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextScriptInfo = SpendingScript _ownTxOutRef (P.Just (unsafeFromBuiltinData P.. getDatum -> datum :: BountyDatum))
        , scriptContextTxInfo =
          TxInfo
            { txInfoOutputs
            }
        }
    ) =
    let targetPkh = beneficiary datum
     in -- VULNERABILITY: Only checks ANY output goes to beneficiary
        -- Does not verify the output is specifically for THIS spend
        if hasOutputToBeneficiary targetPkh txInfoOutputs
          then BI.unitval
          else P.traceError "No output to beneficiary"
validator _ = P.traceError "Invalid script context - expected SpendingScript with datum"

{- | VULNERABLE: Check that ANY output pays to the beneficiary.
This is the vulnerability - it doesn't check that the output is
uniquely associated with this particular spend.
-}
{-# INLINEABLE hasOutputToBeneficiary #-}
hasOutputToBeneficiary :: PubKeyHash -> [TxOut] -> P.Bool
hasOutputToBeneficiary _ [] = P.False
hasOutputToBeneficiary targetPkh (TxOut{txOutAddress} : rest) =
  case toPubKeyHash txOutAddress of
    P.Just pkh ->
      if pkh P.== targetPkh
        then P.True
        else hasOutputToBeneficiary targetPkh rest
    P.Nothing -> hasOutputToBeneficiary targetPkh rest
