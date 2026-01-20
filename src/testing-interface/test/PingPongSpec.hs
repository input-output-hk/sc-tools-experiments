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
  propPingPongSecureAgainstOutputRedirect,

  -- * Basic threat model example
  basicThreatModel,
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
 )
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.TestingInterface (
  Actions (Actions),
  RunOptions (mcOptions),
  TestingInterface (..),
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
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import PlutusLedgerApi.V2 qualified as PV2
import Scripts qualified
import Scripts.PingPong qualified as PingPong
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
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
        model{pmTxIn = Just (C.TxIn (C.TxId "dummy") (C.TxIx 0))}
      PlayRound redeemer ->
        let newState = case redeemer of
              PingPong.Ping -> PingPong.Pinged
              PingPong.Pong -> PingPong.Ponged
              PingPong.Stop -> PingPong.Stopped
         in model{pmState = newState}

  perform model action = case action of
    Initialize state -> do
      liftIO $ putStrLn $ "Initializing contract with state: " ++ show state
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
      liftIO $ putStrLn $ "Playing round: " ++ show redeemer
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
              case PV2.fromData @PingPong.PingPongState (C.toPlutusData $ C.getScriptData scriptData) of
                Just actualState -> do
                  let matches = actualState == pmState model
                  unless matches $
                    liftIO $
                      putStrLn $
                        "STATE MISMATCH! Model: " ++ show (pmState model) ++ ", Blockchain: " ++ show actualState
                  pure matches
                Nothing -> do
                  liftIO $ putStrLn "Failed to decode datum as PingPongState"
                  pure False
            _ -> do
              liftIO $ putStrLn "Expected inline datum but got something else"
              pure False
   where
    unless True _ = pure ()
    unless False m = m

  monitoring _state _action prop = prop

  threatModels = [unprotectedScriptOutput]

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
    (tx, utxo) <- pingPongVulnerableScenario

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
  pingPongVulnerableScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  pingPongVulnerableScenario = do
    let value = 10_000_000
        -- Use VULNERABLE script
        scriptHash = C.hashScript (plutusScript Scripts.pingPongVulnerableScript)

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
        (execBuildTx $ Scripts.playPingPongVulnerableRound Defaults.networkId value Scripts.Pong txIn)
        TrailingChange
        []

    pure (playTx, utxoBefore)

{- | Test that demonstrates the SECURE pingPong is NOT vulnerable to output redirection.

This test runs the unprotectedScriptOutput threat model against the SECURE
pingPong validator. The threat model attempts to redirect script outputs to the
signer's address while preserving the datum.

Since the secure pingPong validates BOTH datum state transitions AND output
addresses, this threat model should NOT find a vulnerability - the modified
transaction should fail validation.

NO 'expectFailure' - the threat model should NOT find a vulnerability.

NOTE: This test uses runThreatModelM which runs INSIDE MockchainT for full
Phase 1 + Phase 2 validation with re-balancing and re-signing.
-}
propPingPongSecureAgainstOutputRedirect :: RunOptions -> Property
propPingPongSecureAgainstOutputRedirect opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- pingPongSecureScenario

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
      monitor (counterexample "Testing SECURE pingPong - should NOT be vulnerable")
      pure prop
 where
  pingPongSecureScenario
    :: ( MonadMockchain C.ConwayEra m
       , MonadError (BalanceTxError C.ConwayEra) m
       , MonadFail m
       )
    => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
  pingPongSecureScenario = do
    let value = 10_000_000
        -- Use SECURE script
        scriptHash = C.hashScript (plutusScript Scripts.pingPongValidatorScript)

    -- Deploy pingPong with secure script
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

    -- Play a round - this transaction IS validated by the SECURE script
    let txIn = C.TxIn (C.getTxId $ C.getTxBody deployTx) (C.TxIx 0)
    playTx <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playPingPongRound Defaults.networkId value Scripts.Pong txIn)
        TrailingChange
        []
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let txIn2 = C.TxIn (C.getTxId $ C.getTxBody playTx) (C.TxIx 0)
    playTx2 <-
      tryBalanceAndSubmit
        mempty
        Wallet.w1
        (execBuildTx $ Scripts.playPingPongRound Defaults.networkId value Scripts.Ping txIn2)
        TrailingChange
        []

    pure (playTx2, utxoBefore)

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
