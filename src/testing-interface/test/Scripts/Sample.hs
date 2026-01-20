{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}

-- A plutus validator that only succeeds if the redeemer is identical to the script's input index
module Scripts.Sample (
  validator,
  -- mintingPolicy,
  SampleRedeemer (..),
) where

import PlutusLedgerApi.V1.Scripts (Redeemer (..))
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
 )
import PlutusTx (unstableMakeIsData)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit)
import PlutusTx.Prelude qualified as P
import Prelude qualified as Haskell

data SampleRedeemer = SampleRedeemer
  { flag1 :: Haskell.Bool
  , flag2 :: Haskell.Bool
  }

PlutusTx.unstableMakeIsData ''SampleRedeemer

{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> SampleRedeemer{flag1, flag2})
        }
    ) = if flag1 P.&& flag2 then BI.unitval else P.traceError "Flags not both true"

-- {-# INLINEABLE mintingPolicy #-}
-- mintingPolicy :: BuiltinData -> BuiltinUnit
-- mintingPolicy (unsafeFromBuiltinData -> ScriptContext{scriptContextScriptInfo = MintingScript ownCs, scriptContextTxInfo = TxInfo{txInfoMint}, scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> idx :: P.Integer)}) =
--   let mintList = flattenValue (mintValueMinted txInfoMint)
--       isOwnIndex (cs, _, _) = cs P.== ownCs
--       ownIndex = P.findIndex isOwnIndex mintList
--    in if ownIndex P.== (P.Just idx) then BI.unitval else P.traceError "Different indices"
-- mintingPolicy _ = P.error ()
