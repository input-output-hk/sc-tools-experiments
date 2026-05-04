{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module PingPongSpec (
  -- * TestingInterface model
  PingPongModel,

  -- * Test helpers
  pingPongMultipleRounds,

  -- * Property tests
  propPingPongWithThreatModel,
  propPingPongVulnerableToOutputRedirect,
  propPingPongVulnerableToLargeData,
  propPingPongVulnerableToLargeValue,

  -- * Basic threat model example
  basicThreatModel,

  -- * Test tree
  pingPongTests,
) where

import Cardano.Api qualified as C
import Control.Lens ((^.))
import Control.Monad (void)
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.Trans (lift)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  MonadMockchain,
  getUtxo,
 )
import Convex.Class qualified
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
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
  TestingInterface (..),
  ThreatModelsFor (..),
  genAction,
  mockchainFailsWithOptions,
  mockchainSucceedsWithOptions,
  propRunActionsWithOptions,
  runTestingMonadT,
 )
import Convex.ThreatModel (
  SigningWallet (SignWith),
  ThreatModel (Named),
  ThreatModelEnv (..),
  counterexampleTM,
  ensure,
  getTxOutputs,
  paragraph,
  runThreatModel,
  runThreatModelMQuiet,
 )
import Convex.ThreatModel.InvalidDatumIndex (invalidDatumIndexAttackWith)
import Convex.ThreatModel.InvalidScriptPurpose (invalidScriptPurposeAttack)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.MissingOutputDatum (missingOutputDatumAttack)
import Convex.ThreatModel.OutputDatumHashMissing (outputDatumHashMissingAttack)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map

import Scripts qualified
import Scripts.PingPong qualified as PingPong
import Scripts.PingPong.Vulnerable qualified as VulnerablePingPong

import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
  testProperty,
 )
import Test.Tasty.QuickCheck qualified as QC

data ScriptDatumStyle = InlineDatumStyle | DatumHashStyle
  deriving (Show, Eq)

data PingPongModel = PingPongModel
  { modelState :: PingPong.PingPongState
  , modelScriptUtxoCount :: Int
  , modelDatumStyle :: ScriptDatumStyle
  , modelInitialized :: Bool
  }
  deriving (Show, Eq)

instance TestingInterface PingPongModel where
  data Action PingPongModel
    = StartWithInlineDatum
    | StartWithDatumHash
    | PlayRound PingPong.PingPongRedeemer
    | DeployExtraScriptUtxo
    | SpendTwoScriptInputs PingPong.PingPongRedeemer
    deriving (Show, Eq)

  initialize =
    pure
      PingPongModel
        { modelState = PingPong.Pinged
        , modelScriptUtxoCount = 0
        , modelDatumStyle = InlineDatumStyle
        , modelInitialized = False
        }

  arbitraryAction PingPongModel{modelInitialized, modelScriptUtxoCount, modelState, modelDatumStyle} =
    if not modelInitialized
      then QC.elements [StartWithInlineDatum, StartWithDatumHash]
      else
        let
          allRedeemers = [PingPong.Ping, PingPong.Pong, PingPong.Stop]
          genSingle = PlayRound <$> QC.elements allRedeemers
          genDual = SpendTwoScriptInputs <$> QC.elements allRedeemers
         in
          case modelScriptUtxoCount of
            1
              | modelState /= PingPong.Stopped ->
                  case modelDatumStyle of
                    InlineDatumStyle ->
                      QC.frequency
                        [ (7, genSingle)
                        , (3, pure DeployExtraScriptUtxo)
                        ]
                    DatumHashStyle ->
                      genSingle
              | otherwise -> genSingle
            _
              | modelScriptUtxoCount >= 2 && modelDatumStyle == InlineDatumStyle ->
                  genDual
            _ ->
              genSingle

  precondition :: PingPongModel -> Action PingPongModel -> Bool
  precondition PingPongModel{modelState, modelScriptUtxoCount, modelInitialized, modelDatumStyle} action =
    case action of
      StartWithInlineDatum -> not modelInitialized
      StartWithDatumHash -> not modelInitialized
      PlayRound redeemer ->
        modelInitialized
          && modelScriptUtxoCount == 1
          && isValidTransition modelState redeemer
      DeployExtraScriptUtxo ->
        modelInitialized
          && modelScriptUtxoCount == 1
          && modelDatumStyle == InlineDatumStyle
          && modelState /= PingPong.Stopped
      SpendTwoScriptInputs redeemer ->
        modelInitialized
          && modelScriptUtxoCount >= 2
          && modelDatumStyle == InlineDatumStyle
          && isValidTransition modelState redeemer

  perform model@PingPongModel{modelState, modelScriptUtxoCount, modelDatumStyle} action = do
    utxos <- getScriptUtxosSorted
    let spendByStyle txIn redeemer =
          case modelDatumStyle of
            InlineDatumStyle ->
              BuildTx.spendPlutusInlineDatum
                txIn
                Scripts.pingPongValidatorScript
                redeemer
            DatumHashStyle ->
              BuildTx.spendPlutus
                txIn
                Scripts.pingPongValidatorScript
                modelState
                redeemer

        mkContinuation lovelace redeemer =
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            (nextStateFor redeemer)
            C.NoStakeAddress
            (C.lovelaceToValue lovelace)

        nextStyleFor _ _ = InlineDatumStyle

    case action of
      StartWithInlineDatum -> do
        let initialState = PingPong.Pinged
            value = 10_000_000
        void $
          tryBalanceAndSubmit
            mempty
            Wallet.w1
            ( execBuildTx $
                BuildTx.payToScriptInlineDatum
                  Defaults.networkId
                  scriptHash
                  initialState
                  C.NoStakeAddress
                  (C.lovelaceToValue value)
            )
            TrailingChange
            []
        pure
          model
            { modelState = initialState
            , modelScriptUtxoCount = 1
            , modelDatumStyle = InlineDatumStyle
            , modelInitialized = True
            }
      StartWithDatumHash -> do
        let initialState = PingPong.Pinged
            value = 10_000_000
        void $
          tryBalanceAndSubmit
            mempty
            Wallet.w1
            ( execBuildTx $
                BuildTx.payToScriptDatumHash
                  Defaults.networkId
                  (plutusScript Scripts.pingPongValidatorScript)
                  initialState
                  C.NoStakeAddress
                  (C.lovelaceToValue value)
            )
            TrailingChange
            []
        pure
          model
            { modelState = initialState
            , modelScriptUtxoCount = 1
            , modelDatumStyle = DatumHashStyle
            , modelInitialized = True
            }
      PlayRound redeemer -> do
        case utxos of
          [] -> fail "No UTxO found at script address"
          ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) : _) -> do
            let lovelace = C.selectLovelace (C.fromMaryValue val)
                outputStyle = nextStyleFor redeemer modelDatumStyle
            void $
              tryBalanceAndSubmit
                mempty
                Wallet.w1
                ( execBuildTx $ do
                    spendByStyle txIn redeemer
                    mkContinuation lovelace redeemer
                )
                TrailingChange
                []
            pure
              PingPongModel
                { modelState = nextStateFor redeemer
                , modelScriptUtxoCount = modelScriptUtxoCount
                , modelDatumStyle = outputStyle
                , modelInitialized = True
                }
      DeployExtraScriptUtxo -> do
        let value = 10_000_000
        void $
          tryBalanceAndSubmit
            mempty
            Wallet.w1
            ( execBuildTx $ case modelDatumStyle of
                InlineDatumStyle ->
                  BuildTx.payToScriptInlineDatum
                    Defaults.networkId
                    scriptHash
                    modelState
                    C.NoStakeAddress
                    (C.lovelaceToValue value)
                DatumHashStyle ->
                  BuildTx.payToScriptDatumHash
                    Defaults.networkId
                    (plutusScript Scripts.pingPongValidatorScript)
                    modelState
                    C.NoStakeAddress
                    (C.lovelaceToValue value)
            )
            TrailingChange
            []
        pure model{modelScriptUtxoCount = modelScriptUtxoCount + 1}
      SpendTwoScriptInputs redeemer -> do
        case utxos of
          ((txIn1, C.TxOut _ (C.TxOutValueShelleyBased _ val1) _ _) : (txIn2, C.TxOut _ (C.TxOutValueShelleyBased _ val2) _ _) : _) -> do
            let lovelace1 = C.selectLovelace (C.fromMaryValue val1)
                lovelace2 = C.selectLovelace (C.fromMaryValue val2)
                outputStyle = nextStyleFor redeemer modelDatumStyle
            void $
              tryBalanceAndSubmit
                mempty
                Wallet.w1
                ( execBuildTx $ do
                    spendByStyle txIn1 redeemer
                    spendByStyle txIn2 redeemer
                    mkContinuation lovelace1 redeemer
                    mkContinuation lovelace2 redeemer
                )
                TrailingChange
                []
            pure
              model
                { modelState = nextStateFor redeemer
                , modelScriptUtxoCount = modelScriptUtxoCount
                , modelDatumStyle = outputStyle
                }
          _ -> fail "Need at least two script UTxOs to spend in one transaction"

  validate PingPongModel{modelState, modelScriptUtxoCount, modelDatumStyle, modelInitialized} =
    if not modelInitialized
      then pure True
      else do
        utxos <- getScriptUtxosSorted
        let actualCount = length utxos
        if actualCount /= modelScriptUtxoCount
          then pure False
          else
            if actualCount == 0
              then pure (modelState == PingPong.Stopped)
              else do
                let styleConsistent = all checkStyle utxos
                pure styleConsistent
   where
    checkStyle (_, C.TxOut _ _ (C.TxOutDatumInline _ _) _) = modelDatumStyle == InlineDatumStyle
    checkStyle (_, C.TxOut _ _ (C.TxOutDatumHash _ _) _) = modelDatumStyle == DatumHashStyle
    checkStyle _ = False

  monitoring _state _action prop = prop

instance ThreatModelsFor PingPongModel where
  threatModels =
    [ largeDataAttackWith 10
    , largeValueAttackWith 10
    , invalidDatumIndexAttackWith 5
    , invalidScriptPurposeAttack Scripts.pingPongValidatorScript
    , missingOutputDatumAttack
    , outputDatumHashMissingAttack
    , unprotectedScriptOutput
    ]

  expectedVulnerabilities = []

plutusScript :: (C.IsPlutusScriptLanguage lang) => C.PlutusScript lang -> C.Script lang
plutusScript = C.PlutusScript C.plutusScriptVersion

isValidTransition :: PingPong.PingPongState -> PingPong.PingPongRedeemer -> Bool
isValidTransition st red = case (st, red) of
  (PingPong.Pinged, PingPong.Pong) -> True
  (PingPong.Pinged, PingPong.Stop) -> True
  (PingPong.Ponged, PingPong.Ping) -> True
  (PingPong.Ponged, PingPong.Stop) -> True
  _ -> False

nextStateFor :: PingPong.PingPongRedeemer -> PingPong.PingPongState
nextStateFor red = case red of
  PingPong.Ping -> PingPong.Pinged
  PingPong.Pong -> PingPong.Ponged
  PingPong.Stop -> PingPong.Stopped

scriptAddress :: C.AddressInEra C.ConwayEra
scriptAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript (C.hashScript (plutusScript Scripts.pingPongValidatorScript)))
    C.NoStakeAddress

scriptHash :: C.ScriptHash
scriptHash = C.hashScript (plutusScript Scripts.pingPongValidatorScript)

getScriptUtxosSorted
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.TxOut C.CtxUTxO C.ConwayEra)]
getScriptUtxosSorted = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
  pure
    [ (txIn, txOut)
    | (txIn, txOut@(C.TxOut addr _ _ _)) <- Map.toAscList utxos
    , addr == scriptAddress
    ]

{- | A simple threat model that demonstrates the integration pattern.

This threat model checks basic transaction properties. It serves as an
example of how to integrate ThreatModel with TestingInterface.

NOTE: For proper threat model testing of output protection:
1. The UTxO set should be captured at each transaction submission time
   (not at the end of all transactions, as done here for simplicity)
2. Only transactions with script inputs should be tested for output protection
   (since only then does a validator run that could enforce the output)

The DoubleSatisfaction threat model from the library is designed for more
sophisticated scenarios where you need to test that scripts properly protect
their outputs from being redirected.
-}
basicThreatModel :: ThreatModel ()
basicThreatModel = Named "Basic Threat Model" $ do
  -- Get transaction outputs to verify we can access transaction data
  outputs <- getTxOutputs
  -- Skip empty transactions (shouldn't happen, but be defensive)
  ensure (not $ null outputs)
  -- Log information about the transaction being tested
  counterexampleTM $
    paragraph
      [ "Transaction has"
      , show (length outputs)
      , "outputs."
      ]
  -- This trivially passes - it demonstrates the integration pattern
  -- For real threat models, you would use shouldValidate/shouldNotValidate
  -- to check specific security properties
  pure ()

{- | Property test that runs PingPong actions and then checks a
threat model against all submitted transactions.

This demonstrates how to integrate threat models with TestingInterface.
-}
propPingPongWithThreatModel :: RunOptions -> Property
propPingPongWithThreatModel opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the mockchain and collect transactions
  result <- runTestingMonadT params $ do
    initialState <- initialize @PingPongModel
    -- Generate and execute actions
    let go (0 :: Int) s = pure s
        go i s = do
          mAction <- lift $ genAction s
          case mAction of
            Just action -> perform s action >>= go (i - 1)
            Nothing -> pure s

    _ <- go 10 initialState

    -- Collect submitted transactions
    txs <- Convex.Class.getTxs
    -- Get the current UTxO set
    ledgerUtxo <- Convex.Class.getUtxo
    pure (txs, ledgerUtxo)

  case result of
    (Left err, _) -> fail (show err)
    (Right (txs, ledgerUtxo), _finalState) -> do
      -- Convert ledger UTxO to cardano-api UTxO
      let utxo = fromLedgerUTxO C.shelleyBasedEra ledgerUtxo
          pparams' = params ^. ledgerProtocolParameters

      -- Create ThreatModelEnv for each transaction
      let envs =
            [ ThreatModelEnv
                { currentTx = tx
                , currentUTxOs = utxo
                , pparams = pparams'
                }
            | tx <- txs
            ]

      -- Run the basic threat model
      -- This demonstrates the integration pattern
      monitor (counterexample $ "Tested " ++ show (length txs) ++ " transactions")
      pure $ runThreatModel basicThreatModel envs

{- | Test that demonstrates the VULNERABLE pingPong's vulnerability to output redirection.

This test runs the unprotectedScriptOutput threat model against the VULNERABLE
pingPong validator. The threat model attempts to redirect script outputs to the
signer's address while preserving the datum.

Since the vulnerable pingPong only validates datum state transitions but doesn't
check that outputs go back to the script address, this threat model WILL find
a vulnerability - the modified transaction validates when it shouldn't.

We use 'expectFailure' because finding the vulnerability means the
QuickCheck property fails (which is the expected behavior for a vulnerable
script).

NOTE: This test uses runThreatModelM which runs INSIDE MockchainT for full
Phase 1 + Phase 2 validation with re-balancing and re-signing.
-}
propPingPongVulnerableToOutputRedirect :: RunOptions -> Property
propPingPongVulnerableToOutputRedirect opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- vulnerablePingPongScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    -- Use runThreatModelMQuiet to suppress verbose counterexample output
    lift $ runThreatModelMQuiet (SignWith Wallet.w1) unprotectedScriptOutput [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> pure prop
 where
  vulnerablePingPongScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  vulnerablePingPongScenario = do
    let value = 10_000_000
        -- Use VULNERABLE script
        sh = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                sh
                Scripts.Pinged
                C.NoStakeAddress
                (C.lovelaceToValue value)
            )
        )
        TrailingChange
        []

    -- Capture UTxO BEFORE playing a round (contains the script UTxO)
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Play a round - this transaction IS validated by the VULNERABLE script
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
    playTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playVulnerablePingPongRound Defaults.networkId value VulnerablePingPong.Pong txIn)
        TrailingChange
        []

    pure (playTx, utxoBefore)

{- | Test that demonstrates the vulnerable PingPong script IS vulnerable to
large data attacks. The 'largeDataAttackWith' threat model should find that
bloated datums are accepted by the script.

This test is expected to "fail" from QuickCheck's perspective - which means
the threat model successfully found the vulnerability.
-}
propPingPongVulnerableToLargeData :: RunOptions -> Property
propPingPongVulnerableToLargeData opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- vulnerablePingPongLargeDataScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run threat model inside MockchainT
    -- Use runThreatModelMQuiet to suppress verbose counterexample output
    lift $ runThreatModelMQuiet (SignWith Wallet.w1) (largeDataAttackWith 10) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> pure prop
 where
  vulnerablePingPongLargeDataScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  vulnerablePingPongLargeDataScenario = do
    let value = 10_000_000
        -- Use VULNERABLE script (uses unstableMakeIsData - permissive parsing)
        sh = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                sh
                Scripts.Pinged
                C.NoStakeAddress
                (C.lovelaceToValue value)
            )
        )
        TrailingChange
        []

    -- Capture UTxO BEFORE playing a round (contains the script UTxO as input)
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Play a round to create a transaction with script output
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
    playTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playVulnerablePingPongRound Defaults.networkId value VulnerablePingPong.Pong txIn)
        TrailingChange
        []

    pure (playTx, utxoBefore)

{- | Test that demonstrates the vulnerable PingPong script IS vulnerable to
large value attacks. The 'largeValueAttackWith' threat model should find that
extra tokens can be added to the script output's value.

This test is expected to "fail" from QuickCheck's perspective - which means
the threat model successfully found the vulnerability.

The vulnerable PingPong script only validates datum state transitions but doesn't
check the Value structure of outputs, making it susceptible to having junk tokens
added to its UTxOs.
-}
propPingPongVulnerableToLargeValue :: RunOptions -> Property
propPingPongVulnerableToLargeValue opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- vulnerablePingPongLargeValueScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run threat model inside MockchainT
    -- Use runThreatModelMQuiet to suppress verbose counterexample output
    lift $ runThreatModelMQuiet (SignWith Wallet.w1) (largeValueAttackWith 10) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> pure prop
 where
  vulnerablePingPongLargeValueScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  vulnerablePingPongLargeValueScenario = do
    let value = 10_000_000
        -- Use VULNERABLE script (doesn't validate Value structure)
        sh = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                sh
                Scripts.Pinged
                C.NoStakeAddress
                (C.lovelaceToValue value)
            )
        )
        TrailingChange
        []

    -- Capture UTxO BEFORE playing a round (contains the script UTxO as input)
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Play a round to create a transaction with script output
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
    playTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playVulnerablePingPongRound Defaults.networkId value VulnerablePingPong.Pong txIn)
        TrailingChange
        []

    pure (playTx, utxoBefore)

pingPongMultipleRounds
  :: forall era m
   . ( MonadMockchain era m
     , MonadError (BalanceTxError era) m
     , MonadFail m
     , C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => Scripts.PingPongState
  -> [Scripts.PingPongRedeemer]
  -> m ()
pingPongMultipleRounds fstState redeemers = do
  let value = 10_000_000
  -- this is the inital state and will not be validated
  -- we should prepare the state based on what we are about to play
  let txBody =
        execBuildTx
          ( BuildTx.payToScriptInlineDatum
              Defaults.networkId
              (C.hashScript (plutusScript Scripts.pingPongValidatorScript))
              -- we should start with Pinged if redeemer is Pong
              -- and Ponged if redeemer is Ping
              fstState
              C.NoStakeAddress
              (C.lovelaceToValue value)
          )
  tx <- tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
  _ <- play value tx redeemers
  pure ()
 where
  play _ tx [] = pure tx
  play value tx (redeemer : xs) = do
    newTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playPingPongRound Defaults.networkId value redeemer (getTxIn tx))
        TrailingChange
        []
    play value newTx xs

  getTxIn tx = C.TxIn (C.getTxId $ C.getTxBody tx) (C.TxIx 0)

-- | All PingPong tests grouped together
pingPongTests :: Options C.ConwayEra -> RunOptions -> TestTree
pingPongTests opts runOpts =
  testGroup
    "ping-pong"
    [ testCase
        "Ping and Pong should succeed"
        ( mockchainSucceedsWithOptions opts $
            pingPongMultipleRounds Scripts.Pinged [Scripts.Pong]
        )
    , testCase
        "Pong and Ping should succeed"
        ( mockchainSucceedsWithOptions opts $
            pingPongMultipleRounds Scripts.Ponged [Scripts.Ping]
        )
    , testCase
        "Ping and Ping should fail"
        ( mockchainFailsWithOptions
            opts
            (pingPongMultipleRounds Scripts.Pinged [Scripts.Ping])
            (\_ -> pure ())
        )
    , testCase
        "Pong and Pong should fail"
        ( mockchainFailsWithOptions
            opts
            (pingPongMultipleRounds Scripts.Ponged [Scripts.Pong])
            (\_ -> pure ())
        )
    , testCase
        "Stop after Ping should succeed"
        ( mockchainSucceedsWithOptions opts $
            pingPongMultipleRounds Scripts.Ponged [Scripts.Ping, Scripts.Stop]
        )
    , testCase
        "Stop after Pong should succeed"
        ( mockchainSucceedsWithOptions opts $
            pingPongMultipleRounds Scripts.Pinged [Scripts.Pong, Scripts.Stop]
        )
    , testCase
        "Stop after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (pingPongMultipleRounds Scripts.Stopped [Scripts.Stop])
            (\_ -> pure ())
        )
    , testCase
        "Ping after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (pingPongMultipleRounds Scripts.Stopped [Scripts.Ping])
            (\_ -> pure ())
        )
    , testCase
        "Pong after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (pingPongMultipleRounds Scripts.Stopped [Scripts.Pong])
            (\_ -> pure ())
        )
    , propRunActionsWithOptions @PingPongModel
        "Property-based test ping-pong validator with TestingInterface"
        runOpts
    , testProperty
        "PingPong VULNERABLE to unprotected output redirect"
        (propPingPongVulnerableToOutputRedirect runOpts)
    , testProperty
        "PingPong VULNERABLE to large data attack"
        (propPingPongVulnerableToLargeData runOpts)
    , testProperty
        "PingPong VULNERABLE to large value attack"
        (propPingPongVulnerableToLargeValue runOpts)
    ]
