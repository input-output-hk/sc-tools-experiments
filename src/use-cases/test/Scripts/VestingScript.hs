{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}
-- 1.1.0.0 will be enabled in conway
{-# OPTIONS_GHC -fobject-code -fno-ignore-interface-pragmas -fno-omit-interface-pragmas -fplugin-opt PlutusTx.Plugin:target-version=1.1.0.0 #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:defer-errors #-}

-- | Scripts used for testing
module Scripts.VestingScript (
  vestingValidatorScript,
  Vesting.VestingParams (..),
) where

import Cardano.Api qualified as C
import Contracts.Vesting qualified as Vesting
import Convex.PlutusTx (compiledCodeToScript)
import PlutusTx (BuiltinData, CompiledCode)
import PlutusTx qualified
import PlutusTx.Prelude (BuiltinUnit)

-- | Compiling a parameterized validator for 'Scripts.Vesting.validator'
vestingValidatorCompiled :: Vesting.VestingParams -> CompiledCode (BuiltinData -> BuiltinUnit)
vestingValidatorCompiled params =
  case $$(PlutusTx.compile [||Vesting.validator||])
    `PlutusTx.applyCode` PlutusTx.liftCodeDef params of
    Left err -> error err
    Right cc -> cc

-- | Serialized validator for 'Scripts.Vesting.validator'
vestingValidatorScript :: Vesting.VestingParams -> C.PlutusScript C.PlutusScriptV3
vestingValidatorScript = compiledCodeToScript . vestingValidatorCompiled
