{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
-- 1.1.0.0 will be enabled in conway
{-# OPTIONS_GHC -fobject-code -fno-ignore-interface-pragmas -fno-omit-interface-pragmas -fplugin-opt PlutusTx.Plugin:target-version=1.1.0.0 #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:defer-errors #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

-- | Scripts used for testing
module Scripts (
  -- * Sample
  sampleValidatorScript,
  spendSample,
  Sample.SampleRedeemer (..),

  -- * PingPong (Secure version)
  pingPongValidatorScript,
  playPingPongRound,
  pingPongCovIdx,
  PingPong.PingPongRedeemer (..),
  PingPong.PingPongState (..),

  -- * PingPong Vulnerable (for threat model demonstration)
  vulnerablePingPongScript,
  playVulnerablePingPongRound,

  -- * Bounty (Secure version - resists double satisfaction)
  bountyValidatorScript,
  claimBounty,
  Bounty.BountyDatum (..),
  Bounty.BountyRedeemer (..),

  -- * Bounty Vulnerable (for double satisfaction threat model demonstration)
  bountyVulnerableScript,
  claimBountyVulnerable,
) where

import Cardano.Api (NetworkId)
import Cardano.Api qualified as C
import Convex.BuildTx (MonadBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.PlutusTx (compiledCodeToScript)
import Convex.Scripts (toHashableScriptData)
import Convex.Utils (inBabbage)
import PlutusLedgerApi.V3 qualified as PV3
import PlutusTx (BuiltinData, CompiledCode)
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx
import PlutusTx.Code (getCovIdx)
import PlutusTx.Coverage (CoverageIndex)
import PlutusTx.Prelude (BuiltinUnit)
import Scripts.Bounty qualified as Bounty
import Scripts.Bounty.Vulnerable.DoubleSatisfaction qualified as BountyVulnerable
import Scripts.PingPong qualified as PingPong
import Scripts.PingPong.Vulnerable qualified as VulnerablePingPong
import Scripts.Sample qualified as Sample

sampleValidatorCompiled :: CompiledCode (BuiltinData -> BuiltinUnit)
sampleValidatorCompiled = $$(PlutusTx.compile [||Sample.validator||])

sampleValidatorScript :: C.PlutusScript C.PlutusScriptV3
sampleValidatorScript = compiledCodeToScript sampleValidatorCompiled

pingPongValidatorCompiled :: CompiledCode (BuiltinData -> BuiltinUnit)
pingPongValidatorCompiled = $$(PlutusTx.compile [||PingPong.validator||])

pingPongValidatorScript :: C.PlutusScript C.PlutusScriptV3
pingPongValidatorScript = compiledCodeToScript pingPongValidatorCompiled

pingPongCovIdx :: CoverageIndex
pingPongCovIdx = getCovIdx $$(PlutusTx.compile [||PingPong.validator||])

-- | Vulnerable PingPong validator (for threat model demonstration)
vulnerablePingPongCompiled :: CompiledCode (BuiltinData -> BuiltinUnit)
vulnerablePingPongCompiled = $$(PlutusTx.compile [||VulnerablePingPong.validator||])

vulnerablePingPongScript :: C.PlutusScript C.PlutusScriptV3
vulnerablePingPongScript = compiledCodeToScript vulnerablePingPongCompiled

spendSample
  :: forall era m
   . (C.IsAlonzoBasedEra era, C.HasScriptLanguageInEra C.PlutusScriptV3 era)
  => (MonadBuildTx era m)
  => Sample.SampleRedeemer
  -> C.TxIn
  -> m ()
spendSample redeemer txi =
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            sampleValidatorScript
            (C.ScriptDatumForTxIn $ Just $ toHashableScriptData ())
            redeemer
   in BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness

plutusScript :: (C.IsPlutusScriptLanguage lang) => C.PlutusScript lang -> C.Script lang
plutusScript = C.PlutusScript C.plutusScriptVersion

-- | Convert a cardano-api TxIn to a Plutus TxOutRef
txInToTxOutRef :: C.TxIn -> PV3.TxOutRef
txInToTxOutRef (C.TxIn txId (C.TxIx ix)) =
  PV3.TxOutRef
    { PV3.txOutRefId = PV3.TxId $ PlutusTx.toBuiltin $ C.serialiseToRawBytes txId
    , PV3.txOutRefIdx = fromIntegral ix
    }

playPingPongRound
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => (MonadBuildTx era m)
  => NetworkId
  -> C.Lovelace
  -> PingPong.PingPongRedeemer
  -> C.TxIn
  -> m ()
playPingPongRound networkId value redeemer txi = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            pingPongValidatorScript
            (C.ScriptDatumForTxIn $ Nothing)
            redeemer
  BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness
  BuildTx.payToScriptInlineDatum
    networkId
    (C.hashScript (plutusScript pingPongValidatorScript))
    ( case redeemer of
        PingPong.Ping -> PingPong.Pinged
        PingPong.Pong -> PingPong.Ponged
        PingPong.Stop -> PingPong.Stopped
    )
    C.NoStakeAddress
    (C.lovelaceToValue value)

-- | Play a round using the VULNERABLE PingPong validator (for threat model demo)
playVulnerablePingPongRound
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => (MonadBuildTx era m)
  => NetworkId
  -> C.Lovelace
  -> VulnerablePingPong.PingPongRedeemer
  -> C.TxIn
  -> m ()
playVulnerablePingPongRound networkId value redeemer txi = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            vulnerablePingPongScript
            (C.ScriptDatumForTxIn $ Nothing)
            redeemer
  BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness
  BuildTx.payToScriptInlineDatum
    networkId
    (C.hashScript (plutusScript vulnerablePingPongScript))
    ( case redeemer of
        VulnerablePingPong.Ping -> VulnerablePingPong.Pinged
        VulnerablePingPong.Pong -> VulnerablePingPong.Ponged
        VulnerablePingPong.Stop -> VulnerablePingPong.Stopped
    )
    C.NoStakeAddress
    (C.lovelaceToValue value)

-- Bounty validators

bountyValidatorCompiled :: CompiledCode (BuiltinData -> BuiltinUnit)
bountyValidatorCompiled = $$(PlutusTx.compile [||Bounty.validator||])

bountyValidatorScript :: C.PlutusScript C.PlutusScriptV3
bountyValidatorScript = compiledCodeToScript bountyValidatorCompiled

-- | Vulnerable Bounty validator (for double satisfaction threat model demo)
bountyVulnerableCompiled :: CompiledCode (BuiltinData -> BuiltinUnit)
bountyVulnerableCompiled = $$(PlutusTx.compile [||BountyVulnerable.validator||])

bountyVulnerableScript :: C.PlutusScript C.PlutusScriptV3
bountyVulnerableScript = compiledCodeToScript bountyVulnerableCompiled

{- | Claim a bounty using the SECURE validator.
The output to the beneficiary must include the spent TxOutRef as inline datum.
-}
claimBounty
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => (MonadBuildTx era m)
  => C.TxIn
  -- ^ The bounty UTxO to spend
  -> C.AddressInEra era
  -- ^ The beneficiary address (must match datum)
  -> C.Lovelace
  -- ^ Amount to pay to beneficiary
  -> m ()
claimBounty txi beneficiaryAddr value = inBabbage @era $ do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            bountyValidatorScript
            (C.ScriptDatumForTxIn Nothing)
            Bounty.Claim
  BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness
  -- SECURE: Output includes the TxOutRef as inline datum
  -- This prevents double satisfaction as each spend needs its own tagged output
  let txOutRef = txInToTxOutRef txi
      dat = C.TxOutDatumInline C.babbageBasedEra (toHashableScriptData txOutRef)
      val = BuildTx.mkTxOutValue (C.lovelaceToValue value)
      txo = C.TxOut beneficiaryAddr val dat C.ReferenceScriptNone
  BuildTx.prependTxOut txo

{- | Claim a bounty using the VULNERABLE validator.
The output to the beneficiary does NOT include any identifying datum.
-}
claimBountyVulnerable
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => (MonadBuildTx era m)
  => C.TxIn
  -- ^ The bounty UTxO to spend
  -> C.AddressInEra era
  -- ^ The beneficiary address (must match datum)
  -> C.Lovelace
  -- ^ Amount to pay to beneficiary
  -> m ()
claimBountyVulnerable txi beneficiaryAddr value = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            bountyVulnerableScript
            (C.ScriptDatumForTxIn Nothing)
            BountyVulnerable.Claim
  BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness
  -- VULNERABLE: No datum on the output - any output to beneficiary satisfies multiple spends
  BuildTx.payToAddress beneficiaryAddr (C.lovelaceToValue value)
