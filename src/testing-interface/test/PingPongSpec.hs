{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module PingPongSpec (
  -- * TestingInterface model
  PingPongModel (..),

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
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
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
  MockchainT,
  fromLedgerUTxO,
  runMockchain0IOWith,
 )
import Convex.MockChain.CoinSelection (
  balanceAndSubmit,
  tryBalanceAndSubmit,
 )
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (
  Options (Options, params),
  mockchainFailsWithOptions,
  mockchainSucceedsWithOptions,
 )
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.TestingInterface (
  Actions (Actions),
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (
  ThreatModel,
  ThreatModelEnv (..),
  counterexampleTM,
  ensure,
  getTxOutputs,
  paragraph,
  runThreatModel,
  runThreatModelM,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import PlutusTx.Builtins (dataToBuiltinData)
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
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

-- | Model state for the PingPong contract testing interface
data PingPongModel = PingPongModel
  { pmState :: PingPong.PingPongState
  -- ^ Current state of the PingPong contract
  , pmTxIn :: Maybe C.TxIn
  -- ^ Reference to the current UTxO locked at the contract
  , pmValue :: C.Lovelace
  -- ^ Amount of lovelace locked in the contract
  }
  deriving (Show, Eq)

instance TestingInterface PingPongModel where
  data Action PingPongModel
    = Initialize PingPong.PingPongState
    | -- \^ Deploy the contract with an initial state
      PlayRound PingPong.PingPongRedeemer
    -- \^ Play a round (Ping, Pong, or Stop)
    deriving (Show, Eq)

  initialState =
    PingPongModel
      { pmState = PingPong.Pinged
      , pmTxIn = Nothing
      , pmValue = 10_000_000
      }

  arbitraryAction model =
    case pmTxIn model of
      Nothing ->
        -- Contract not yet deployed, must initialize
        pure $ Initialize (pmState model)
      Just _ ->
        -- Contract deployed, generate any action - precondition will filter
        QC.elements [PlayRound PingPong.Ping, PlayRound PingPong.Pong, PlayRound PingPong.Stop]

  precondition model action =
    case action of
      Initialize _ ->
        -- Can only initialize if contract not yet deployed
        pmTxIn model == Nothing
      PlayRound redeemer ->
        -- Can only play if contract is deployed
        case pmTxIn model of
          Nothing -> False
          Just _ -> case (pmState model, redeemer) of
            -- From Stopped, no valid actions (contract is finished)
            (PingPong.Stopped, _) -> False
            -- From Pinged, we can Pong or Stop
            (PingPong.Pinged, PingPong.Pong) -> True
            (PingPong.Pinged, PingPong.Stop) -> True
            (PingPong.Pinged, PingPong.Ping) -> False
            -- From Ponged, we can Ping or Stop
            (PingPong.Ponged, PingPong.Ping) -> True
            (PingPong.Ponged, PingPong.Stop) -> True
            (PingPong.Ponged, PingPong.Pong) -> False

  nextState model action =
    case action of
      Initialize _state ->
        -- Mark contract as deployed (actual TxIn will be set during perform)
        model{pmTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))}
      PlayRound redeemer ->
        let newState = case redeemer of
              PingPong.Ping -> PingPong.Pinged
              PingPong.Pong -> PingPong.Ponged
              PingPong.Stop -> PingPong.Stopped
         in model{pmState = newState}

  perform model action = case action of
    Initialize state -> do
      -- liftIO $ putStrLn $ "Initializing contract with state: " ++ show state
      -- Deploy the contract with the initial state
      let txBody =
            execBuildTx
              ( BuildTx.payToScriptInlineDatum
                  Defaults.networkId
                  (C.hashScript (plutusScript Scripts.pingPongValidatorScript))
                  state
                  C.NoStakeAddress
                  (C.lovelaceToValue $ pmValue model)
              )
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to initialize contract: " ++ show err
        Right _ -> pure ()
    PlayRound redeemer -> do
      -- liftIO $ putStrLn $ "Playing round: " ++ show redeemer
      -- Find the UTxO at the script address
      let scriptHash = C.hashScript (plutusScript Scripts.pingPongValidatorScript)
          scriptAddr = C.makeShelleyAddressInEra C.shelleyBasedEra Defaults.networkId (C.PaymentCredentialByScript scriptHash) C.NoStakeAddress
      -- Query all UTxOs from the blockchain
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
      -- Find UTxOs at the script address
      let scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == scriptAddr) utxos
      case Map.toList scriptUtxos of
        [] -> fail "No UTxO found at script address"
        ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) : _) -> do
          -- Get the value from the UTxO
          let lovelace = C.selectLovelace (C.fromMaryValue val)
          -- Execute the round
          runExceptT
            ( balanceAndSubmit
                mempty
                Wallet.w1
                (execBuildTx $ Scripts.playPingPongRound Defaults.networkId lovelace redeemer txIn)
                TrailingChange
                []
            )
            >>= \case
              Left err -> fail $ "Failed to play round: " ++ show err
              Right _ -> pure ()

  validate model = case pmTxIn model of
    Nothing -> pure True -- No contract deployed yet
    Just _ -> do
      -- Query the actual state from the blockchain
      let scriptHash = C.hashScript (plutusScript Scripts.pingPongValidatorScript)
          scriptAddr =
            C.makeShelleyAddressInEra
              C.shelleyBasedEra
              Defaults.networkId
              (C.PaymentCredentialByScript scriptHash)
              C.NoStakeAddress
      utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
      let C.UTxO utxos = utxoSet
          scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == scriptAddr) utxos

      case Map.toList scriptUtxos of
        [] ->
          -- No UTxO found - contract must have been consumed
          -- This is valid if model state is Stopped
          pure (pmState model == PingPong.Stopped)
        ((_, C.TxOut _ _ datum _) : _) -> do
          -- Extract the actual state from the datum
          case datum of
            C.TxOutDatumInline _ scriptData -> do
              let actualState = unsafeFromBuiltinData @PingPong.PingPongState (dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
                  matches = actualState == pmState model
              unless matches $
                liftIO $
                  putStrLn $
                    "STATE MISMATCH! Model: " ++ show (pmState model) ++ ", Blockchain: " ++ show actualState
              pure matches
            _ -> do
              liftIO $ putStrLn "Expected inline datum but got something else"
              pure False
   where
    unless True _ = pure ()
    unless False m = m

  monitoring _state _action prop = prop

  threatModels = [basicThreatModel, unprotectedScriptOutput, largeDataAttackWith 10, largeValueAttackWith 10]

plutusScript :: (C.IsPlutusScriptLanguage lang) => C.PlutusScript lang -> C.Script lang
plutusScript = C.PlutusScript C.plutusScriptVersion

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
basicThreatModel = do
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
propPingPongWithThreatModel :: RunOptions -> Actions PingPongModel -> Property
propPingPongWithThreatModel opts (Actions actions) = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the mockchain and collect transactions
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ do
    -- Execute all actions
    _ <- foldMActions (initialState @PingPongModel) actions
    -- Collect submitted transactions
    txs <- Convex.Class.getTxs
    -- Get the current UTxO set
    ledgerUtxo <- Convex.Class.getUtxo
    pure (txs, ledgerUtxo)

  case result of
    ((txs, ledgerUtxo), _finalState) -> do
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
 where
  foldMActions :: PingPongModel -> [Action PingPongModel] -> MockchainT C.ConwayEra IO PingPongModel
  foldMActions s [] = pure s
  foldMActions s (a : as) = do
    perform s a
    foldMActions (nextState s a) as

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
    lift $ runThreatModelM Wallet.w1 unprotectedScriptOutput [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing VULNERABLE pingPong for unprotected script output vulnerability")
      pure prop
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
        scriptHash = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
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
    lift $ runThreatModelM Wallet.w1 (largeDataAttackWith 10) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing VULNERABLE pingPong for large data attack vulnerability")
      pure prop
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
        scriptHash = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
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
    lift $ runThreatModelM Wallet.w1 (largeValueAttackWith 10) [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing VULNERABLE pingPong for large value attack vulnerability")
      pure prop
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
        scriptHash = C.hashScript (plutusScript Scripts.vulnerablePingPongScript)

    -- Deploy pingPong with vulnerable script
    deployTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        ( execBuildTx
            ( BuildTx.payToScriptInlineDatum
                Defaults.networkId
                scriptHash
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

-- | All PingPong tests grouped together
pingPongTests :: Options C.ConwayEra -> RunOptions -> TestTree
pingPongTests opts runOpts =
  testGroup
    "ping-pong"
    [ testCase
        "Ping and Pong should succeed"
        ( mockchainSucceedsWithOptions opts $
            failOnError
              (pingPongMultipleRounds Scripts.Pinged [Scripts.Pong])
        )
    , testCase
        "Pong and Ping should succeed"
        ( mockchainSucceedsWithOptions opts $
            failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Ping])
        )
    , testCase
        "Ping and Ping should fail"
        ( mockchainFailsWithOptions
            opts
            (failOnError (pingPongMultipleRounds Scripts.Pinged [Scripts.Ping]))
            (\_ -> pure ())
        )
    , testCase
        "Pong and Pong should fail"
        ( mockchainFailsWithOptions
            opts
            (failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Pong]))
            (\_ -> pure ())
        )
    , testCase
        "Stop after Ping should succeed"
        ( mockchainSucceedsWithOptions opts $
            failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Ping, Scripts.Stop])
        )
    , testCase
        "Stop after Pong should succeed"
        ( mockchainSucceedsWithOptions opts $
            failOnError (pingPongMultipleRounds Scripts.Pinged [Scripts.Pong, Scripts.Stop])
        )
    , testCase
        "Stop after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Stop]))
            (\_ -> pure ())
        )
    , testCase
        "Ping after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Ping]))
            (\_ -> pure ())
        )
    , testCase
        "Pong after Stop should fail"
        ( mockchainFailsWithOptions
            opts
            (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Pong]))
            (\_ -> pure ())
        )
    , propRunActionsWithOptions @PingPongModel
        "Property-based test with TestingInterface"
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
