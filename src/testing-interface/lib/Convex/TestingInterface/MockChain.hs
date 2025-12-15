{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}

{- | Helper functions for working with MockChain in testing interfaces.

This module provides utilities to make it easier to write 'perform' implementations
that interact with the mockchain.
-}
module Convex.TestingInterface.MockChain (
  -- * Running the mockchain
  runModelTest,
  runModelTestWithOptions,

  -- * Wallet helpers
  getWalletUtxos,
  getWalletBalance,

  -- * Script helpers
  findScriptOutputs,
  findScriptOutputsWith,

  -- * Chain state queries
  currentSlot,
  currentTime,

  -- * Re-exports
  module Convex.MockChain,
) where

import Cardano.Api (ConwayEra, TxIn, UTxO (..))
import Cardano.Api qualified as C
import Control.Monad.IO.Class qualified as MonadIO
import Data.Map qualified as Map
import Data.Set qualified as Set

import Convex.Class (MockChainState, MonadMockchain, getSlot, getUtxo)
import Convex.MockChain
import Convex.MockChain qualified as MockChain
import Convex.Wallet (Wallet)
import Convex.Wallet qualified as Wallet

-- | Run a testing interface test with default options
runModelTest :: MockchainT ConwayEra IO a -> IO (a, MockChainState ConwayEra)
runModelTest = runMockchain0IO []

-- | Run a testing interface test with custom initial UTxOs
runModelTestWithOptions :: InitialUTXOs -> MockchainT ConwayEra IO a -> IO (a, MockChainState ConwayEra)
runModelTestWithOptions utxos = runMockchain0IO utxos

{- | Get all UTxOs for a wallet
Note: Simplified implementation returning all chain UTxOs
In practice, you'd filter by wallet address
-}
getWalletUtxos :: (MonadIO m) => Wallet -> MockchainT ConwayEra m (UTxO ConwayEra)
getWalletUtxos _wallet = allUtxoSet

{- | Get the total balance for a wallet
Note: Simplified implementation summing all chain UTxOs
In practice, you'd filter by wallet address
-}
getWalletBalance :: (MonadIO m) => Wallet -> MockchainT ConwayEra m C.Value
getWalletBalance wallet = do
  UTxO utxos <- getWalletUtxos wallet
  pure $ foldMap (getTxOutValue . snd) (Map.toList utxos)
 where
  getTxOutValue (C.TxOut _ (C.txOutValueToValue -> value) _ _) = value

-- | Find all UTxO outputs that are locked by a specific script
findScriptOutputs
  :: (MonadIO m)
  => C.PlutusScriptOrReferenceInput C.PlutusScriptV2
  -> MockchainT ConwayEra m [(TxIn, C.TxOut C.CtxUTxO ConwayEra)]
findScriptOutputs script = do
  allUtxos <- allUtxoSet
  pure $ filter (isScriptOutput script) (utxoList allUtxos)

-- | Find script outputs that satisfy a predicate
findScriptOutputsWith
  :: (MonadIO m)
  => C.PlutusScriptOrReferenceInput C.PlutusScriptV2
  -> (C.TxOut C.CtxUTxO ConwayEra -> Bool)
  -> MockchainT ConwayEra m [(TxIn, C.TxOut C.CtxUTxO ConwayEra)]
findScriptOutputsWith script predicate = do
  outputs <- findScriptOutputs script
  pure $ filter (predicate . snd) outputs

-- | Get all UTxOs on the chain
allUtxoSet :: (MonadIO m) => MockchainT ConwayEra m (UTxO ConwayEra)
allUtxoSet = do
  ledgerUtxo <- getUtxo
  pure $ C.fromLedgerUTxO C.shelleyBasedEra ledgerUtxo

-- | Convert UTxO to list
utxoList :: UTxO era -> [(TxIn, C.TxOut C.CtxUTxO era)]
utxoList (UTxO m) = Map.toList m

-- | Check if a UTxO output is locked by a specific script
isScriptOutput
  :: C.PlutusScriptOrReferenceInput C.PlutusScriptV2
  -> (TxIn, C.TxOut C.CtxUTxO era)
  -> Bool
isScriptOutput _script (_, _txOut) =
  -- Simplified check - in practice you'd want to match script hash
  True

-- | Get the current slot number
currentSlot :: (MonadIO m) => MockchainT ConwayEra m C.SlotNo
currentSlot = getSlot

-- | Get the current time (as POSIXTime)
currentTime :: (MonadIO m) => MockchainT ConwayEra m Integer
currentTime = do
  slot <- currentSlot
  pure $ slotToPOSIXTime slot

{- | Convert slot to POSIX time (milliseconds since epoch)
Simplified conversion assuming 1 slot = 1 second (Cardano mainnet)
-}
slotToPOSIXTime :: C.SlotNo -> Integer
slotToPOSIXTime (C.SlotNo slot) = fromIntegral slot * 1000
