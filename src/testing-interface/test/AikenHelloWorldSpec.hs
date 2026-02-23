{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF Hello World validator using TestingInterface.

This module demonstrates property-based testing of a simple "password check" contract.
The CTF Hello World validator allows anyone to lock funds at the script address, and
anyone who knows the correct password ("Hello CTF!") can claim the locked funds.

The Aiken types encode as:
- @Datum@: Option<Void> - any datum is accepted (ignored by validator)
- @Redeemer { msg: ByteArray }@ = @Constr 0 [msg_bytes]@
-}
module AikenHelloWorldSpec (
  -- * TestingInterface model
  HelloWorldModel (..),

  -- * Test tree
  aikenHelloWorldTests,
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map

import Paths_convex_testing_interface qualified as Pkg
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx

import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck ()
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- CTF Hello World Redeemer type (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The redeemer for the CTF Hello World contract.

Aiken encodes this as: @Constr 0 [msg_bytes]@
The validator checks that msg == "Hello CTF!"
-}
data HelloWorldRedeemer = HelloWorldRedeemer
  { hwMsg :: PlutusTx.BuiltinByteString
  }
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''HelloWorldRedeemer

-- | The correct password that unlocks the contract
correctPassword :: PlutusTx.BuiltinByteString
correctPassword = "Hello CTF!"

-- | An incorrect password for testing failure cases
wrongPassword :: PlutusTx.BuiltinByteString
wrongPassword = "Wrong Password"

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_hello_world" validator from the embedded blueprint
loadCtfHelloWorldScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadCtfHelloWorldScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_hello_world.ctf_hello_world.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_hello_world.ctf_hello_world.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Hello World script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE ctfHelloWorldScript #-}
ctfHelloWorldScript :: C.PlutusScript C.PlutusScriptV3
ctfHelloWorldScript = unsafePerformIO loadCtfHelloWorldScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the CTF Hello World script
helloWorldScriptHash :: C.ScriptHash
helloWorldScriptHash = C.hashScript (plutusScript ctfHelloWorldScript)

-- | Address of the CTF Hello World script on the default network
helloWorldAddress :: C.AddressInEra C.ConwayEra
helloWorldAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript helloWorldScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Lock funds at the CTF Hello World script address.

The script accepts any datum (Option<Void>), so we use unit () as a simple datum.
-}
lockFunds
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.Lovelace
  -> m ()
lockFunds networkId value = do
  -- Use unit () as the datum - the validator ignores it
  BuildTx.payToScriptInlineDatum
    networkId
    helloWorldScriptHash
    ()
    C.NoStakeAddress
    (C.lovelaceToValue value)

{- | Unlock funds from the CTF Hello World script address.

Spends the UTxO at the script address using the provided redeemer.
The validator checks that the redeemer message equals "Hello CTF!".
-}
unlockFunds
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -> C.Value
  -> Wallet
  -> HelloWorldRedeemer
  -> m ()
unlockFunds networkId txIn value recipientWallet redeemer = do
  let recipientAddr = addressInEra networkId recipientWallet
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            ctfHelloWorldScript
            (C.ScriptDatumForTxIn Nothing)
            redeemer
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.payToAddress recipientAddr value

-- ----------------------------------------------------------------------------
-- Helper to find script UTxO
-- ----------------------------------------------------------------------------

-- | Find the UTxO at the hello world script address
findHelloWorldUtxo
  :: (MonadMockchain C.ConwayEra m)
  => m (Maybe (C.TxIn, C.Value))
findHelloWorldUtxo = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == helloWorldAddress) utxos
  case Map.toList scriptUtxos of
    [] -> pure Nothing
    ((txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) : _) ->
      pure $ Just (txIn, C.fromMaryValue val)

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenHelloWorldUnitTests :: TestTree
aikenHelloWorldUnitTests =
  testGroup
    "ctf hello world unit tests"
    [ testCase "lock funds at script address" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ lockFunds Defaults.networkId 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findHelloWorldUtxo
            case result of
              Nothing -> liftIO $ assertFailure "Expected UTxO at script address"
              Just _ -> pure ()
    , testCase "lock then unlock with correct password" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock funds
            let lockTxBody = execBuildTx $ lockFunds @C.ConwayEra Defaults.networkId 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody TrailingChange []

            -- Find and unlock
            result <- findHelloWorldUtxo
            case result of
              Nothing -> liftIO $ assertFailure "Expected UTxO at script address"
              Just (txIn, value) -> do
                let unlockTxBody =
                      execBuildTx $
                        unlockFunds @C.ConwayEra
                          Defaults.networkId
                          txIn
                          value
                          Wallet.w2
                          (HelloWorldRedeemer correctPassword)
                void $ tryBalanceAndSubmit mempty Wallet.w2 unlockTxBody TrailingChange []
    , testCase "lock then unlock with wrong password fails" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock funds
            let lockTxBody = execBuildTx $ lockFunds @C.ConwayEra Defaults.networkId 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody TrailingChange []

            -- Find and try to unlock with wrong password
            result <- findHelloWorldUtxo
            case result of
              Nothing -> liftIO $ assertFailure "Expected UTxO at script address"
              Just (txIn, value) -> do
                let unlockTxBody =
                      execBuildTx $
                        unlockFunds @C.ConwayEra
                          Defaults.networkId
                          txIn
                          value
                          Wallet.w2
                          (HelloWorldRedeemer wrongPassword)
                -- This should fail validation
                unlockResult <- runExceptT $ balanceAndSubmit mempty Wallet.w2 unlockTxBody TrailingChange []
                case unlockResult of
                  Left _err -> pure () -- Expected: balancing/validation fails
                  Right (Left _err) -> pure () -- Expected: validation fails
                  Right (Right _) ->
                    liftIO $ assertFailure "ERROR: Unlock with wrong password should have failed!"
    , testCase "lock, unlock, lock again (stateless)" $
        mockchainSucceeds $
          failOnError $ do
            -- First lock
            let lockTxBody1 = execBuildTx $ lockFunds @C.ConwayEra Defaults.networkId 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody1 TrailingChange []

            -- Unlock
            result1 <- findHelloWorldUtxo
            case result1 of
              Nothing -> liftIO $ assertFailure "Expected UTxO at script address"
              Just (txIn, value) -> do
                let unlockTxBody =
                      execBuildTx $
                        unlockFunds @C.ConwayEra
                          Defaults.networkId
                          txIn
                          value
                          Wallet.w2
                          (HelloWorldRedeemer correctPassword)
                void $ tryBalanceAndSubmit mempty Wallet.w2 unlockTxBody TrailingChange []

            -- Lock again
            let lockTxBody2 = execBuildTx $ lockFunds @C.ConwayEra Defaults.networkId 15_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w3 lockTxBody2 TrailingChange []

            -- Verify UTxO exists again
            result2 <- findHelloWorldUtxo
            case result2 of
              Nothing -> liftIO $ assertFailure "Expected UTxO at script address after re-lock"
              Just _ -> pure ()
    ]

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Hello World contract
data HelloWorldModel = HelloWorldModel
  { hwLocked :: Bool
  -- ^ Whether funds are locked at script
  , hwValue :: C.Lovelace
  -- ^ Amount locked
  , hwTxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script (for tracking)
  }
  deriving stock (Show, Eq)

instance TestingInterface HelloWorldModel where
  -- Actions for CTF Hello World: lock funds and unlock (correct password only)
  data Action HelloWorldModel
    = LockFunds C.Lovelace
    | -- \^ Lock some ADA at the script
      UnlockCorrect
    -- \^ Unlock with correct password "Hello CTF!"
    deriving stock (Show, Eq)

  initialState =
    HelloWorldModel
      { hwLocked = False
      , hwValue = 0
      , hwTxIn = Nothing
      }

  -- Generate actions: LockFunds when not locked, UnlockCorrect when locked
  arbitraryAction model
    | hwLocked model = pure UnlockCorrect
    | otherwise = LockFunds <$> genLovelace
   where
    genLovelace = fromInteger <$> QC.choose (5_000_000, 50_000_000)

  precondition model (LockFunds _) = not (hwLocked model)
  precondition model UnlockCorrect = hwLocked model

  nextState model action = case action of
    LockFunds amount ->
      model
        { hwLocked = True
        , hwValue = amount
        , hwTxIn = Nothing -- Will be set by perform
        }
    UnlockCorrect ->
      model
        { hwLocked = False
        , hwValue = 0
        , hwTxIn = Nothing
        }

  perform _model action = case action of
    LockFunds amount -> do
      let txBody = execBuildTx $ lockFunds @C.ConwayEra Defaults.networkId amount
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to lock funds: " ++ show err
        Right _ -> pure ()
    UnlockCorrect -> do
      result <- findHelloWorldUtxo
      case result of
        Nothing -> fail "No UTxO found at hello world script address"
        Just (txIn, value) -> do
          let txBody =
                execBuildTx $
                  unlockFunds @C.ConwayEra
                    Defaults.networkId
                    txIn
                    value
                    Wallet.w2
                    (HelloWorldRedeemer correctPassword)
          runExceptT (balanceAndSubmit mempty Wallet.w2 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to unlock funds: " ++ show err
            Right _ -> pure ()

  validate model = do
    result <- findHelloWorldUtxo
    case (hwLocked model, result) of
      (False, Nothing) -> pure True -- Not locked, no UTxO - correct
      (True, Just (_, value)) ->
        -- Locked with UTxO - check value matches
        pure $ C.selectLovelace value == hwValue model
      (False, Just _) -> pure False -- Model says not locked but UTxO exists
      (True, Nothing) -> pure False -- Model says locked but no UTxO

  monitoring _state _action prop = prop

  -- No threat models for this simple contract
  threatModels = []

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Hello World tests grouped together
aikenHelloWorldTests :: RunOptions -> TestTree
aikenHelloWorldTests runOpts =
  testGroup
    "ctf hello world"
    [ aikenHelloWorldUnitTests
    , propRunActionsWithOptions @HelloWorldModel
        "property-based testing"
        runOpts
    ]
