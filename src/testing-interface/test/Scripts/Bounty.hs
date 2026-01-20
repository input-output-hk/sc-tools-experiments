{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Secure Bounty validator.

This validator releases funds to a beneficiary. It properly validates that
the output paying to the beneficiary includes a unique datum (the spent
input's TxOutRef), preventing double satisfaction attacks.

See 'Scripts.Bounty.Vulnerable.DoubleSatisfaction' for the vulnerable version
used to demonstrate the threat model.

== Double Satisfaction Attack

The attack occurs when a script only checks "there exists an output to X"
without uniquely identifying which output belongs to this spend. An attacker
can bundle multiple script spends where a single output satisfies all of them.

== Secure Pattern

This validator requires that the output to the beneficiary includes an inline
datum containing the TxOutRef of the input being spent. This ensures each
spend requires its own dedicated output.
-}
module Scripts.Bounty (
  validator,
  BountyDatum (..),
  BountyRedeemer (..),
) where

import PlutusLedgerApi.V1.Address (toPubKeyHash)
import PlutusLedgerApi.V1.Crypto (PubKeyHash)
import PlutusLedgerApi.V1.Scripts (Datum (getDatum))
import PlutusLedgerApi.V2.Tx (OutputDatum (OutputDatum), TxOut (..))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  ScriptInfo (SpendingScript),
  TxInfo (..),
 )
import PlutusLedgerApi.V3.Tx (TxOutRef)
import PlutusTx (makeIsDataIndexed, unstableMakeIsData)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P
import Prelude qualified as Haskell

-- | Datum specifying who can claim the bounty
newtype BountyDatum = BountyDatum
  { beneficiary :: PubKeyHash
  -- ^ The public key hash that can claim these funds
  }
  deriving stock (Haskell.Eq, Haskell.Show)

-- | Redeemer for claiming the bounty
data BountyRedeemer = Claim
  deriving stock (Haskell.Eq, Haskell.Show)

PlutusTx.unstableMakeIsData ''BountyDatum
PlutusTx.makeIsDataIndexed ''BountyRedeemer [('Claim, 0)]

{- | SECURE VALIDATOR

This validator checks:
1. There exists an output paying to the beneficiary
2. That output has an inline datum containing THIS input's TxOutRef

The second check prevents double satisfaction: each spend of a Bounty UTxO
requires a dedicated output tagged with the specific input being spent.
-}
{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextScriptInfo = SpendingScript ownTxOutRef (P.Just (unsafeFromBuiltinData P.. getDatum -> datum :: BountyDatum))
        , scriptContextTxInfo =
          TxInfo
            { txInfoOutputs
            }
        }
    ) =
    let targetPkh = beneficiary datum
     in if hasValidOutput targetPkh ownTxOutRef txInfoOutputs
          then BI.unitval
          else P.traceError "No valid output to beneficiary with correct datum"
validator _ = P.traceError "Invalid script context - expected SpendingScript with datum"

{- | SECURITY CRITICAL: Check that an output exists that:
1. Pays to the beneficiary (by public key hash)
2. Has an inline datum equal to our TxOutRef

This prevents double satisfaction because each Bounty spend requires
an output uniquely tagged with that specific input's reference.
-}
{-# INLINEABLE hasValidOutput #-}
hasValidOutput :: PubKeyHash -> TxOutRef -> [TxOut] -> P.Bool
hasValidOutput _ _ [] = P.False
hasValidOutput targetPkh ownRef (TxOut{txOutAddress, txOutDatum} : rest) =
  case toPubKeyHash txOutAddress of
    P.Just pkh ->
      if pkh P.== targetPkh P.&& checkDatum txOutDatum ownRef
        then P.True
        else hasValidOutput targetPkh ownRef rest
    P.Nothing -> hasValidOutput targetPkh ownRef rest

{- | Check that the output datum is an inline datum containing our TxOutRef.
This is the key security check that prevents double satisfaction.
-}
{-# INLINEABLE checkDatum #-}
checkDatum :: OutputDatum -> TxOutRef -> P.Bool
checkDatum (OutputDatum (unsafeFromBuiltinData P.. getDatum -> ref :: TxOutRef)) ownRef = ref P.== ownRef
checkDatum _ _ = P.False
