{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

{- | Tests for the Aiken-compiled PingPong validator using TestingInterface.

This module demonstrates that the testing-interface works with
Aiken-compiled (non-PlutusTx) smart contracts. The Aiken PingPong
validator is loaded from a pre-compiled blueprint JSON file.

The Aiken types encode identically to the Haskell types:
- @State { Pinged, Ponged, Stopped }@ = @Constr 0/1/2 []@ = 'PingPongState'
- @Action { Ping, Pong, Stop }@ = @Constr 0/1/2 []@ = 'PingPongRedeemer'

So we reuse 'Scripts.PingPong.PingPongState' and 'Scripts.PingPong.PingPongRedeemer'
as datum/redeemer types.
-}
module AikenPingPongSpec (
  -- * TestingInterface model
  AikenPingPongModel (..),
  playAikenPingPongRound,

  -- * Test tree
  aikenPingPongTests,
) where

import Cardano.Api qualified as C
import Control.Monad (unless, void)
import Control.Monad.IO.Class (MonadIO (..))
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (
  getUtxo,
 )
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (
  fromLedgerUTxO,
 )
import Convex.MockChain.CoinSelection (
  balanceAndSubmit,
 )
import Convex.MockChain.Defaults qualified as Defaults
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  ThreatModelsFor (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import Paths_convex_testing_interface qualified as Pkg
import PlutusTx.Builtins (dataToBuiltinData)
import PlutusTx.IsData.Class (UnsafeFromData (unsafeFromBuiltinData))
import Scripts.PingPong qualified as PingPong
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck ()
import Test.Tasty.QuickCheck qualified as QC

-- | Load the Aiken "ping_pong" validator from the embedded blueprint
loadPingPongScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadPingPongScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ping_pong.ping_pong.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ping_pong.ping_pong.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken PingPong script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE aikenPingPongScript #-}
aikenPingPongScript :: C.PlutusScript C.PlutusScriptV3
aikenPingPongScript = unsafePerformIO loadPingPongScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

{- | Play a round of PingPong using the Aiken validator.

This mirrors 'Scripts.playPingPongRound' but uses the Aiken-compiled script.
-}
playAikenPingPongRound
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.PlutusScript C.PlutusScriptV3
  -> C.NetworkId
  -> C.Lovelace
  -> PingPong.PingPongRedeemer
  -> C.TxIn
  -> m ()
playAikenPingPongRound script networkId value redeemer txi = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            script
            (C.ScriptDatumForTxIn Nothing)
            redeemer
  BuildTx.setScriptsValid >> BuildTx.addInputWithTxBody txi witness
  BuildTx.payToScriptInlineDatum
    networkId
    (C.hashScript (plutusScript script))
    ( case redeemer of
        PingPong.Ping -> PingPong.Pinged
        PingPong.Pong -> PingPong.Ponged
        PingPong.Stop -> PingPong.Stopped
    )
    C.NoStakeAddress
    (C.lovelaceToValue value)

-- | Model state for the Aiken PingPong contract testing interface
data AikenPingPongModel = AikenPingPongModel
  { apmState :: PingPong.PingPongState
  -- ^ Current state of the PingPong contract
  , apmTxIn :: C.TxIn
  -- ^ Reference to the current UTxO locked at the contract
  , apmValue :: C.Lovelace
  -- ^ Amount of lovelace locked in the contract
  }
  deriving (Show, Eq)

instance TestingInterface AikenPingPongModel where
  data Action AikenPingPongModel
    = AikenPlayRound PingPong.PingPongRedeemer
    -- \^ Play a round (Ping, Pong, or Stop)
    deriving (Show, Eq)

  initialize = do
    -- liftIO $ putStrLn $ "[Aiken] Initializing contract with state: " ++ show state
    -- Deploy the contract with the initial state
    let
      model =
        AikenPingPongModel
          { apmState = PingPong.Pinged
          , apmTxIn = C.TxIn dummyTxId (C.TxIx 0)
          , apmValue = 10_000_000
          }
      txBody =
        execBuildTx
          ( BuildTx.payToScriptInlineDatum
              Defaults.networkId
              (C.hashScript (plutusScript aikenPingPongScript))
              (apmState model)
              C.NoStakeAddress
              (C.lovelaceToValue $ apmValue model)
          )
    void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    pure model

  arbitraryAction _model =
    QC.elements [AikenPlayRound PingPong.Ping, AikenPlayRound PingPong.Pong, AikenPlayRound PingPong.Stop]

  precondition model (AikenPlayRound redeemer) =
    case (apmState model, redeemer) of
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

  perform model (AikenPlayRound redeemer) = do
    -- liftIO $ putStrLn $ "[Aiken] Playing round: " ++ show redeemer
    -- Find the UTxO at the script address
    let scriptHash = C.hashScript (plutusScript aikenPingPongScript)
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
        void $
          balanceAndSubmit
            mempty
            Wallet.w1
            (execBuildTx $ playAikenPingPongRound aikenPingPongScript Defaults.networkId lovelace redeemer txIn)
            TrailingChange
            []
    let newState = case redeemer of
          PingPong.Ping -> PingPong.Pinged
          PingPong.Pong -> PingPong.Ponged
          PingPong.Stop -> PingPong.Stopped
     in pure $ model{apmState = newState}

  validate model = do
    -- Query the actual state from the blockchain
    let scriptHash = C.hashScript (plutusScript aikenPingPongScript)
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
        pure (apmState model == PingPong.Stopped)
      ((_, C.TxOut _ _ datum _) : _) -> do
        -- Extract the actual state from the datum
        case datum of
          C.TxOutDatumInline _ scriptData -> do
            let actualState = unsafeFromBuiltinData @PingPong.PingPongState (dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
                matches = actualState == apmState model
            unless matches $
              liftIO $
                putStrLn $
                  "STATE MISMATCH! Model: " ++ show (apmState model) ++ ", Blockchain: " ++ show actualState
            pure matches
          _ -> do
            liftIO $ putStrLn "Expected inline datum but got something else"
            pure False

  monitoring _state _action prop = prop

instance ThreatModelsFor AikenPingPongModel where
  -- The secure Aiken validator should RESIST all these attacks
  threatModels = [unprotectedScriptOutput, largeValueAttackWith 10, largeDataAttackWith 10]

  expectedVulnerabilities = []

-- | All Aiken PingPong tests grouped together
aikenPingPongTests :: RunOptions -> TestTree
aikenPingPongTests runOpts =
  testGroup
    "aiken ping-pong"
    [ propRunActionsWithOptions @AikenPingPongModel
        "Property-based test with TestingInterface"
        runOpts
    ]
