{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

{- | Tests demonstrating that the testing-interface works with
Aiken-compiled (non-PlutusTx) smart contracts.

This module does NOT use Template Haskell or the PlutusTx plugin.
The Aiken validator is loaded from a pre-compiled blueprint JSON file.
-}
module AikenSpec (
  aikenTests,
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (MonadError)
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (Options, mockchainFailsWithOptions, mockchainSucceedsWithOptions)
import Convex.Utils (failOnError)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import Paths_convex_testing_interface qualified as Pkg
import Test.Tasty (TestTree, testGroup, withResource)
import Test.Tasty.HUnit (testCase)

-- | Load the Aiken "check_answer" validator from the embedded blueprint
loadCheckAnswerScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadCheckAnswerScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "check_answer.check_answer.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "check_answer.check_answer.spend not found in Aiken blueprint"

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

{- | Lock Ada at the Aiken script address with an inline datum (Integer),
then spend it with a redeemer (Integer).

The Aiken validator checks: datum + redeemer == 43
-}
aikenSpendTest
  :: forall era m
   . ( MonadMockchain era m
     , MonadError (BalanceTxError era) m
     , MonadFail m
     , C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => C.PlutusScript C.PlutusScriptV3
  -> Integer
  -- ^ datum value (stored number)
  -> Integer
  -- ^ redeemer value (answer)
  -> m ()
aikenSpendTest script storedNumber answer = do
  let scriptHash = C.hashScript (plutusScript script)
  -- Step 1: Lock funds at the Aiken script address with inline datum
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            storedNumber -- Integer datum, wire-compatible with Aiken Int
            C.NoStakeAddress
            (C.lovelaceToValue 10_000_000)
  tx <- tryBalanceAndSubmit mempty Wallet.w1 lockTx TrailingChange []
  let txIn = C.TxIn (C.getTxId (C.getTxBody tx)) (C.TxIx 0)
  -- Step 2: Spend the UTxO using the Aiken validator
  let spendTx =
        execBuildTx $ do
          BuildTx.spendPlutusInlineDatum txIn script answer -- Integer redeemer
          BuildTx.setScriptsValid
  void $ tryBalanceAndSubmit mempty Wallet.w1 spendTx TrailingChange []

{- | All Aiken integration tests.

Uses 'withResource' to load the script once and share it across all test cases.
-}
aikenTests :: Options C.ConwayEra -> TestTree
aikenTests opts =
  withResource loadCheckAnswerScript (\_ -> pure ()) $ \getScript ->
    testGroup
      "aiken simple script"
      [ testCase "Aiken check-answer: correct answer (10 + 33 = 43) succeeds" $ do
          script <- getScript
          mockchainSucceedsWithOptions opts $
            failOnError $
              aikenSpendTest script 10 33
      , testCase "Aiken check-answer: another correct answer (0 + 43 = 43) succeeds" $ do
          script <- getScript
          mockchainSucceedsWithOptions opts $
            failOnError $
              aikenSpendTest script 0 43
      , testCase "Aiken check-answer: wrong answer (10 + 99 != 43) fails" $ do
          script <- getScript
          mockchainFailsWithOptions
            opts
            (failOnError $ aikenSpendTest script 10 99)
            (\_ -> pure ())
      , testCase "Aiken check-answer: edge case negative datum (-4 + 47 = 43) succeeds" $ do
          script <- getScript
          mockchainSucceedsWithOptions opts $
            failOnError $
              aikenSpendTest script (-4) 47
      ]
