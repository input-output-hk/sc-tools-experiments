{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

module BountySpec (
  -- * Test tree
  bountyTests,

  -- * Property tests
  propBountyVulnerableToDoubleSatisfaction,
  propBountySecureAgainstDoubleSatisfaction,
) where

import Cardano.Api qualified as C
import Control.Lens ((^.))
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.Trans (lift)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  MonadMockchain,
  getUtxo,
 )
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (
  fromLedgerUTxO,
  runMockchain0IOWith,
 )
import Convex.MockChain.CoinSelection (
  tryBalanceAndSubmit,
 )
import Convex.MockChain.Defaults qualified as Defaults
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
 )
import Convex.ThreatModel (
  SigningWallet (SignWith),
  ThreatModelEnv (..),
  runThreatModelM,
  runThreatModelMQuiet,
 )
import Convex.ThreatModel.DoubleSatisfaction (doubleSatisfaction)
import Convex.Wallet (addressInEra, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Scripts qualified
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
  testProperty,
 )
import Test.Tasty.QuickCheck qualified as QC

plutusScript :: (C.IsPlutusScriptLanguage lang) => C.PlutusScript lang -> C.Script lang
plutusScript = C.PlutusScript C.plutusScriptVersion

-- | All Bounty tests grouped together
bountyTests :: RunOptions -> TestTree
bountyTests opts =
  testGroup
    "bounty (double satisfaction)"
    [ testProperty
        "Bounty VULNERABLE to double satisfaction"
        (propBountyVulnerableToDoubleSatisfaction opts)
    , testProperty
        "Bounty SECURE against double satisfaction"
        (propBountySecureAgainstDoubleSatisfaction opts)
    ]

{- | Test that demonstrates the VULNERABLE bounty's vulnerability to double satisfaction.

This test runs the doubleSatisfaction threat model against the VULNERABLE
bounty validator. The threat model attempts to bundle a "safe script" input
that satisfies the vulnerable script's output requirement.

Since the vulnerable bounty only checks "some output pays to beneficiary"
without uniquely identifying which output belongs to this spend, the threat
model WILL find a vulnerability.

We use 'expectFailure' because finding the vulnerability means the
QuickCheck property fails (which is the expected behavior for a vulnerable
script).

NOTE: This test uses runThreatModelM which runs INSIDE MockchainT for full
Phase 1 + Phase 2 validation with re-balancing and re-signing.
-}
propBountyVulnerableToDoubleSatisfaction :: RunOptions -> Property
propBountyVulnerableToDoubleSatisfaction opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- bountyVulnerableScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    -- Use runThreatModelMQuiet to suppress verbose counterexample output
    lift $ runThreatModelMQuiet (SignWith Wallet.w1) doubleSatisfaction [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> pure prop
 where
  bountyVulnerableScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  bountyVulnerableScenario = do
    let value = 10_000_000
        -- Use VULNERABLE script
        scriptHash = C.hashScript (plutusScript Scripts.bountyVulnerableScript)
        -- Beneficiary is wallet2
        beneficiaryPkh = transPubKeyHash $ verificationKeyHash Wallet.w2
        bountyDatum = Scripts.BountyDatum beneficiaryPkh

    -- Deploy bounty with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
                bountyDatum
                C.NoStakeAddress
                (C.lovelaceToValue value)
            )
        )
        TrailingChange
        []

    -- Capture UTxO BEFORE claiming (contains the script UTxO)
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Claim the bounty - this transaction pays to wallet2 (beneficiary)
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
        beneficiaryAddr = addressInEra Defaults.networkId Wallet.w2
    claimTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.claimBountyVulnerable txIn beneficiaryAddr value)
        TrailingChange
        []

    pure (claimTx, utxoBefore)

{- | Test that demonstrates the SECURE bounty is NOT vulnerable to double satisfaction.

This test runs the doubleSatisfaction threat model against the SECURE
bounty validator. The threat model attempts to bundle a "safe script" input
that satisfies the script's output requirement.

Since the secure bounty requires each output to include the specific TxOutRef
of the input being spent as an inline datum, the threat model should NOT find
a vulnerability - each spend needs its own uniquely tagged output.

NO 'expectFailure' - the threat model should NOT find a vulnerability.

NOTE: This test uses runThreatModelM which runs INSIDE MockchainT for full
Phase 1 + Phase 2 validation with re-balancing and re-signing.
-}
propBountySecureAgainstDoubleSatisfaction :: RunOptions -> Property
propBountySecureAgainstDoubleSatisfaction opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- bountySecureScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    lift $ runThreatModelM (SignWith Wallet.w1) doubleSatisfaction [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing SECURE bounty - should NOT be vulnerable to double satisfaction")
      pure prop
 where
  bountySecureScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  bountySecureScenario = do
    let value = 10_000_000
        -- Use SECURE script
        scriptHash = C.hashScript (plutusScript Scripts.bountyValidatorScript)
        -- Beneficiary is wallet2
        beneficiaryPkh = transPubKeyHash $ verificationKeyHash Wallet.w2
        bountyDatum = Scripts.BountyDatum beneficiaryPkh

    -- Deploy bounty with secure script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
                bountyDatum
                C.NoStakeAddress
                (C.lovelaceToValue value)
            )
        )
        TrailingChange
        []

    -- Capture UTxO BEFORE claiming (contains the script UTxO)
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Claim the bounty - this transaction pays to wallet2 with TxOutRef datum
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
        beneficiaryAddr = addressInEra Defaults.networkId Wallet.w2
    claimTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.claimBounty txIn beneficiaryAddr value)
        TrailingChange
        []

    pure (claimTx, utxoBefore)
