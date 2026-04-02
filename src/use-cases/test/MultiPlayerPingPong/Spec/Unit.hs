{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module MultiPlayerPingPong.Spec.Unit where

import Cardano.Api qualified as C
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.Utils (failOnError)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet qualified as Wallet
import Convex.Wallet.MockWallet qualified as MockWallet
import MultiPlayerPingPong.Scripts (multiPlayerPingPongValidatorScript)
import MultiPlayerPingPong.Validator (
  BallState (Pinged, Ponged),
  MultiPingPongDatum (..),
  MultiRedeemer (Hit, Stop),
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

-------------------------------------------------------------------------------
-- Unit tests for the MultiPlayerPingPong script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ -- HIT: Happy path
      testCase
        "First hit: index 0->1, Pinged->Ponged"
        (mockchainSucceeds $ failOnError firstHitTest)
    , testCase
        "Middle hit: index 1->2, Ponged->Pinged (3-player game)"
        (mockchainSucceeds $ failOnError middleHitTest)
    , testCase
        "Wrap hit: index 2->0 increments roundCount"
        (mockchainSucceeds $ failOnError wrapHitTest)
    , testCase
        "Two-player wrap: index 1->0 increments round"
        (mockchainSucceeds $ failOnError twoPlayerWrapTest)
    , testCase
        "Large N (5 players): mid-game hit"
        (mockchainSucceeds $ failOnError largeNHitTest)
    , -- HIT: Signer enforcement
      testCase
        "Reject: wrong player signs Hit"
        (mockchainFails (failOnError wrongPlayerHitTest) (\_ -> pure ()))
    , testCase
        "Reject: nobody signs (no valid player signer)"
        (mockchainFails (failOnError noSignerHitTest) (\_ -> pure ()))
    , testCase
        "Reject: third-party outsider signs Hit"
        (mockchainFails (failOnError outsiderSignsHitTest) (\_ -> pure ()))
    , testCase
        "Correct player is co-signer among others"
        (mockchainSucceeds $ failOnError coSignerHitTest)
    , testCase
        "Accept: last player in a 5-player list signs their turn"
        (mockchainSucceeds $ failOnError lastPlayerInFiveHitTest)
    , -- HIT: output state integrity
      testCase
        "Hit reject: ballState does not flip (stays Pinged)"
        (mockchainFails (failOnError ballStateNoFlipTest) (\_ -> pure ()))
    , testCase
        "Hit reject: ballState does not flip (stays Ponged)"
        (mockchainFails (failOnError ballStateNoFlipPongedTest) (\_ -> pure ()))
    , testCase
        "Hit reject: currentIndex advances by 2 instead of 1"
        (mockchainFails (failOnError indexSkipTest) (\_ -> pure ()))
    , testCase
        "Hit reject: currentIndex does not advance (stays the same)"
        (mockchainFails (failOnError indexNoAdvanceTest) (\_ -> pure ()))
    , testCase
        "Hit reject: roundCount increments when index does not wrap"
        (mockchainFails (failOnError roundCountSpuriousIncrementTest) (\_ -> pure ()))
    , testCase
        "Hit reject: roundCount stays same when index wraps"
        (mockchainFails (failOnError roundCountNoIncrementOnWrapTest) (\_ -> pure ()))
    , testCase
        "Hit reject: players list modified in output datum"
        (mockchainFails (failOnError playersListModifiedTest) (\_ -> pure ()))
    , testCase
        "Hit reject: active set to False in output datum"
        (mockchainFails (failOnError activeSetFalseOnHitTest) (\_ -> pure ()))
    , testCase
        "Hit reject: output datum index out of bounds (currentIndex = numPlayers)"
        (mockchainFails (failOnError outputIndexOutOfBoundsTest) (\_ -> pure ()))
    , -- HIT: game-over guard
      testCase
        "Hit reject: game is inactive (active = False) on input datum"
        (mockchainFails (failOnError hitWhenInactiveTest) (\_ -> pure ()))
    , -- STOP: Happy path
      testCase
        "First player stops the game"
        (mockchainSucceeds $ failOnError aliceStopTest)
    , testCase
        "Non-current player stops during Alice turn"
        (mockchainSucceeds $ failOnError bobStopsOnAliceTurnTest)
    , testCase
        "Last player in list stops"
        (mockchainSucceeds $ failOnError lastPlayerStopsTest)
    , testCase
        "Stop accepted when game has many rounds played"
        (mockchainSucceeds $ failOnError stopAfterManyRoundsTest)
    , -- STOP: rejection cases
      testCase
        "Stop reject: outsider (not in players) signs Stop"
        (mockchainFails (failOnError outsiderStopTest) (\_ -> pure ()))
    , testCase
        "Stop reject: no signatory (empty signatories)"
        (mockchainFails (failOnError noSignerStopTest) (\_ -> pure ()))
    , testCase
        "Stop reject: game already stopped (active = False)"
        (mockchainFails (failOnError stopAlreadyStoppedTest) (\_ -> pure ()))
    , -- Integration: full game sequences
      testCase
        "Complete 2-player game: 4 hits then Stop (roundCount = 2)"
        (mockchainSucceeds $ failOnError completeTwoPlayerGameFourHitsThenStopTest)
    , testCase
        "Complete 3-player game: full rotation then Stop (roundCount = 1)"
        (mockchainSucceeds $ failOnError completeThreePlayerFullRotationThenStopTest)
    , testCase
        "Hit reject: replay same input UTxO twice (double spend)"
        (mockchainFails (failOnError replaySameUtxoHitTest) (\_ -> pure ()))
    , testCase
        "5-player: 15 hits (3 full rotations) yields roundCount = 3"
        (mockchainSucceeds $ failOnError fivePlayerThreeRotationsRoundCountTest)
    ]

-------------------------------------------------------------------------------
-- First hit test
--
-- Alice (w1, index 0) signs. Input datum: Pinged, index 0, roundCount 0.
-- Expected output datum:  Ponged, index 1, roundCount 0 (unchanged).
-- Verifies: flipBall, index arithmetic, and signer check all pass together.
-------------------------------------------------------------------------------

firstHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
firstHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  -- Build the players list: [Alice, Bob]
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  -- -------------------------------------------------------------------------
  -- Lock: put the initial datum into the script UTxO
  -- Input datum: Pinged, currentIndex = 0, roundCount = 0, active = True
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  -- A small lovelace value is enough; PingPong carries no native asset.
  let lockedValue = C.lovelaceToValue 2_000_000

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn = C.TxIn txId (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice (index 0) advances the game
  -- Output datum: Ponged, currentIndex = 1, roundCount = 0, active = True
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1 -- advanced by 1 mod 2
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0 -- no wrap-around yet
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          -- Explicitly declare Alice as a required signatory so her PubKeyHash
          -- appears in txInfoSignatories and passes the signer check on-chain.
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          -- Spend the script UTxO with the Hit redeemer
          BuildTx.spendPlutusInlineDatum txIn validatorScript Hit
          -- Return the UTxO to the script with the updated datum.
          -- Value must be preserved exactly (Large Value Attack mitigation)
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  -- Alice signs and submits
  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Middle hit test
--
-- 3-player game: [Alice, Bob, Carol]
-- Setup hit: Alice (index 0) signs. Input: Pinged, index 0. Output: Ponged, index 1.
-- Test hit:   Bob   (index 1) signs. Input: Ponged, index 1. Output: Pinged, index 2.
-- roundCount remains 0 throughout (no wrap-around).
-- Tests the non-wrapping path of the modular index advance.
-------------------------------------------------------------------------------
middleHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
middleHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  -- Build the players list: [Alice, Bob, Carol]
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, index 0, roundCount 0
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit: Alice (index 0) hits. Output: Ponged, index 1, roundCount 0.
  -- This is just scaffolding to reach the state under test.
  -- -------------------------------------------------------------------------

  let afterAliceDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1 -- (0 + 1) mod 3
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0
          , active = True
          }

  let aliceHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterAliceDatum
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice aliceHitTx TrailingChange []

  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Test hit: Bob (index 1) hits. Output: Pinged, index 2, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterBobDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2 -- (1 + 1) mod 3
          , ballState = Pinged -- flipped from Ponged
          , roundCount = 0 -- no wrap-around: next index is 2, not 0
          , active = True
          }

  let bobHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterBobDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty bob bobHitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Wrap hit test
--
-- 3-player game: [Alice, Bob, Carol]
-- Setup hit 1: Alice (index 0). Input: Pinged, index 0. Output: Ponged, index 1.
-- Setup hit 2: Bob   (index 1). Input: Ponged, index 1. Output: Pinged, index 2.
-- Test hit:    Carol (index 2). Input: Pinged, index 2. Output: Ponged, index 0, roundCount 1.
-- This is the only transition where expectedCi == 0, so rc' = rc + 1.
-- Critical boundary test for the roundCount increment logic.
-------------------------------------------------------------------------------
wrapHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrapHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  -- Build the players list: [Alice, Bob, Carol]
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, index 0, roundCount 0
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 1: Alice (index 0). Output: Ponged, index 1, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterAliceDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1 -- (0 + 1) mod 3
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0
          , active = True
          }

  let aliceHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterAliceDatum
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice aliceHitTx TrailingChange []

  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 2: Bob (index 1). Output: Pinged, index 2, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterBobDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2 -- (1 + 1) mod 3
          , ballState = Pinged -- flipped from Ponged
          , roundCount = 0
          , active = True
          }

  let bobHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterBobDatum
            C.NoStakeAddress
            lockedValue

  txId2 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob bobHitTx TrailingChange []

  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Test hit: Carol (index 2) hits. Output: Ponged, index 0, roundCount 1.
  -- (2 + 1) mod 3 == 0, so expectedCi == 0 and rc' = rc + 1 = 1.
  -- -------------------------------------------------------------------------

  let afterCarolDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0 -- (2 + 1) mod 3 wraps back to 0
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 1 -- wrap triggered the increment: 0 + 1
          , active = True
          }

  let carolHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn2 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterCarolDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty carol carolHitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Two-player wrap hit test
--
-- 2-player game: [Alice, Bob]
-- Setup hit: Alice (index 0). Input: Pinged, index 0. Output: Ponged, index 1.
-- Test hit:  Bob   (index 1). Input: Ponged, index 1. Output: Pinged, index 0, roundCount 1.
-- (1 + 1) mod 2 == 0, so expectedCi == 0 and rc' = rc + 1.
-- Minimum-player wrap. Confirms modulo works for N=2.
-------------------------------------------------------------------------------
twoPlayerWrapTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
twoPlayerWrapTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  -- Build the players list: [Alice, Bob]
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, index 0, roundCount 0
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit: Alice (index 0). Output: Ponged, index 1, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterAliceDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1 -- (0 + 1) mod 2
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0
          , active = True
          }

  let aliceHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterAliceDatum
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice aliceHitTx TrailingChange []

  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Test hit: Bob (index 1). Output: Pinged, index 0, roundCount 1.
  -- (1 + 1) mod 2 == 0, so expectedCi == 0 and rc' = rc + 1 = 1.
  -- -------------------------------------------------------------------------

  let afterBobDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0 -- (1 + 1) mod 2 wraps back to 0
          , ballState = Pinged -- flipped from Ponged
          , roundCount = 1 -- wrap triggered the increment: 0 + 1
          , active = True
          }

  let bobHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterBobDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty bob bobHitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Large N hit test
--
-- 5-player game: [Alice, Bob, Carol, Dave, Eve]
-- Setup hits 1-3: Alice (0), Bob (1), Carol (2) advance the game to index 3.
-- Test hit: Dave (index 3). Input: Pinged, index 3. Output: Ponged, index 4.
-- roundCount remains 0 throughout (no wrap-around).
-- Confirms listLength and indexList are correct for larger lists.
-------------------------------------------------------------------------------
largeNHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
largeNHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3
      dave = MockWallet.w4
      eve = MockWallet.w5

  -- Build the players list: [Alice, Bob, Carol, Dave, Eve]
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        , transPubKeyHash (verificationKeyHash dave)
        , transPubKeyHash (verificationKeyHash eve)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, index 0, roundCount 0
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 1: Alice (index 0). Output: Ponged, index 1, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterAliceDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1 -- (0 + 1) mod 5
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0
          , active = True
          }

  let aliceHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterAliceDatum
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice aliceHitTx TrailingChange []

  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 2: Bob (index 1). Output: Pinged, index 2, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterBobDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2 -- (1 + 1) mod 5
          , ballState = Pinged -- flipped from Ponged
          , roundCount = 0
          , active = True
          }

  let bobHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterBobDatum
            C.NoStakeAddress
            lockedValue

  txId2 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob bobHitTx TrailingChange []

  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 3: Carol (index 2). Output: Ponged, index 3, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterCarolDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 3 -- (2 + 1) mod 5
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 0
          , active = True
          }

  let carolHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn2 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterCarolDatum
            C.NoStakeAddress
            lockedValue

  txId3 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty carol carolHitTx TrailingChange []

  let txIn3 = C.TxIn txId3 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Test hit: Dave (index 3). Output: Pinged, index 4, roundCount 0.
  -- (3 + 1) mod 5 == 4, so expectedCi /= 0 and roundCount stays unchanged.
  -- indexList must traverse 4 elements to reach Dave; listLength must return 5.
  -- -------------------------------------------------------------------------

  let afterDaveDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 4 -- (3 + 1) mod 5
          , ballState = Pinged -- flipped from Ponged
          , roundCount = 0 -- no wrap: expectedCi == 4, not 0
          , active = True
          }

  let daveHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash dave)
          BuildTx.spendPlutusInlineDatum txIn3 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterDaveDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty dave daveHitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: wrong player signs Hit (Bob plays Alice's turn)
--
-- 2-player game: [Alice, Bob]
-- currentIndex = 0 (Alice's turn). Bob signs the Hit redeemer.
-- validateHit check 2: elemList currentPlayer signatories must be True.
-- currentPlayer = players !! 0 = Alice's PKH.
-- signatories = [Bob's PKH].
-- Alice's PKH is not in signatories, so the validator must traceError.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
wrongPlayerHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrongPlayerHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Bob signs, but currentIndex = 0 means Alice must sign.
  -- The output datum is otherwise correctly formed — this ensures the test
  -- isolates check 2 (signer) and not any other check.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty bob hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: nobody signs Hit (empty signatories)
--
-- 2-player game: [Alice, Bob]
-- currentIndex = 0 (Alice's turn). No required signatory is declared.
-- validateHit check 2: elemList currentPlayer signatories returns False
-- for any non-empty players list when signatories = [].
-- The validator must traceError "transaction not signed by current player".
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
noSignerHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noSignerHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: no addRequiredSignature call, so txInfoSignatories = [].
  -- elemList (players !! 0) [] = False for any currentPlayer, so the
  -- validator must reject regardless of who submits the transaction.
  -- Alice is used as the fee payer only — her key does not appear in
  -- txInfoSignatories because it is not declared as a required signatory.
  -- The output datum is otherwise correctly formed to isolate check 2.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: third-party outsider signs Hit
--
-- 2-player game: [Alice, Bob]
-- currentIndex = 0 (Alice's turn). Carol (w3) signs — she is not in the
-- players list at all.
-- validateHit check 2: elemList currentPlayer signatories must be True.
-- currentPlayer = players !! 0 = Alice's PKH.
-- signatories = [Carol's PKH].
-- Alice's PKH is not in signatories, so the validator must traceError.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
outsiderSignsHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
outsiderSignsHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3 -- outsider: not in the players list
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- Carol is intentionally absent from the players list.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Carol signs. She is neither the current player (Alice) nor any
  -- other registered player. The output datum is otherwise correctly formed
  -- to isolate check 2 from all other checks.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty carol hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Accept: correct player is co-signer among others
--
-- 2-player game: [Alice, Bob]
-- currentIndex = 0 (Alice's turn). Both Alice and Carol (an outsider) are
-- declared as required signatories. txInfoSignatories = [Carol's PKH, Alice's PKH].
-- validateHit check 2: elemList currentPlayer signatories must return True.
-- currentPlayer = players !! 0 = Alice's PKH.
-- Alice's PKH is present in signatories even though it is not the only entry,
-- so elemList must find it and return True.
-- Confirms elemList returns True when the target is anywhere in the list.
-------------------------------------------------------------------------------
coSignerHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
coSignerHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3 -- outsider co-signer: not in the players list
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: both Carol (outsider) and Alice are declared as required signatories.
  -- txInfoSignatories will contain both PKHs. elemList searches for Alice's
  -- PKH and must find it despite Carol's PKH appearing first.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          -- Carol is declared first so her PKH precedes Alice's in
          -- txInfoSignatories, forcing elemList to recurse past her.
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  -- Alice pays and provides the primary witness; Carol co-signs.
  let carolWitness = C.WitnessPaymentKey (Wallet.getWallet carol)
  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange [carolWitness]

  return ()

-------------------------------------------------------------------------------
-- Accept: last player in a 5-player list signs their turn
--
-- 5-player game: [Alice, Bob, Carol, Dave, Eve]
-- Setup hits 1-4: Alice (0), Bob (1), Carol (2), Dave (3) advance to index 4.
-- Test hit: Eve (index 4) signs. Output: index 0, roundCount 1 (wrap).
-- indexList must traverse all 5 elements to resolve players !! 4 = Eve.
-- Exercises the deepest possible indexList traversal before a wrap.
-------------------------------------------------------------------------------
lastPlayerInFiveHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
lastPlayerInFiveHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3
      dave = MockWallet.w4
      eve = MockWallet.w5

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        , transPubKeyHash (verificationKeyHash dave)
        , transPubKeyHash (verificationKeyHash eve)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, index 0, roundCount 0
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 1: Alice (index 0). Output: Ponged, index 1, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterAliceDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let aliceHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterAliceDatum
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice aliceHitTx TrailingChange []

  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 2: Bob (index 1). Output: Pinged, index 2, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterBobDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let bobHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterBobDatum
            C.NoStakeAddress
            lockedValue

  txId2 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob bobHitTx TrailingChange []

  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 3: Carol (index 2). Output: Ponged, index 3, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterCarolDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 3
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let carolHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn2 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterCarolDatum
            C.NoStakeAddress
            lockedValue

  txId3 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty carol carolHitTx TrailingChange []

  let txIn3 = C.TxIn txId3 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Setup hit 4: Dave (index 3). Output: Pinged, index 4, roundCount 0.
  -- -------------------------------------------------------------------------

  let afterDaveDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 4
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let daveHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash dave)
          BuildTx.spendPlutusInlineDatum txIn3 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterDaveDatum
            C.NoStakeAddress
            lockedValue

  txId4 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty dave daveHitTx TrailingChange []

  let txIn4 = C.TxIn txId4 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Test hit: Eve (index 4). Output: Ponged, index 0, roundCount 1.
  -- (4 + 1) mod 5 == 0, so this is also a wrap — roundCount increments.
  -- indexList must recurse 4 times to resolve players !! 4 = Eve's PKH.
  -- Both the deepest indexList traversal and the wrap path are exercised.
  -- -------------------------------------------------------------------------

  let afterEveDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0 -- (4 + 1) mod 5 wraps to 0
          , ballState = Ponged -- flipped from Pinged
          , roundCount = 1 -- wrap triggered the increment: 0 + 1
          , active = True
          }

  let eveHitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash eve)
          BuildTx.spendPlutusInlineDatum txIn4 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            afterEveDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty eve eveHitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: ballState does not flip on Hit (stays Pinged)
--
-- 2-player game: [Alice, Bob]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: also Pinged — ballState was not flipped to Ponged.
-- validateHit check: bs' /= expectedBs must be False, i.e. the output
-- ballState must equal flipBall inputBallState.
-- flipBall Pinged = Ponged, but bs' = Pinged, so the guard fires and the
-- validator must traceError "ballState must flip".
-- All other fields (currentIndex, roundCount, active, players) are correctly
-- formed to isolate the ballState check exclusively.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
ballStateNoFlipTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
ballStateNoFlipTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, index advances correctly, but ballState
  -- remains Pinged instead of flipping to Ponged.
  -- flipBall Pinged = Ponged, so bs' = Pinged /= Ponged triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Pinged -- wrong: should be Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: ballState does not flip on Hit (stays Ponged)
--
-- 2-player game: [Alice, Bob]
-- Input datum: Ponged, currentIndex = 0. Alice signs (correct player).
-- Output datum: also Ponged — ballState was not flipped to Pinged.
-- validateHit check: bs' /= expectedBs must be False, i.e. the output
-- ballState must equal flipBall inputBallState.
-- flipBall Ponged = Pinged, but bs' = Ponged, so the guard fires and the
-- validator must traceError "ballState must flip".
-- All other fields (currentIndex, roundCount, active, players) are correctly
-- formed to isolate the ballState check exclusively.
-- Mirror of ballStateNoFlipTest for the Ponged→Ponged non-transition.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
ballStateNoFlipPongedTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
ballStateNoFlipPongedTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Ponged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- A Ponged state at index 0 is valid — it simply means the previous hit
  -- produced Ponged and the index wrapped back to 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, index advances correctly, but ballState
  -- remains Ponged instead of flipping to Pinged.
  -- flipBall Ponged = Pinged, so bs' = Ponged /= Pinged triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged -- wrong: should be Pinged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: currentIndex advances by 2 instead of 1 on Hit
--
-- 2-player game: [Alice, Bob]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: currentIndex = 2 — skipped index 1.
-- validateHit check: ci' must equal (ci + 1) mod listLength players.
-- expectedCi = (0 + 1) mod 2 = 1, but ci' = 2, so the guard fires and the
-- validator must traceError "currentIndex did not advance correctly".
-- ballState flips correctly (Pinged → Ponged) and all other fields are
-- correctly formed to isolate the index check exclusively.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
indexSkipTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
indexSkipTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, ballState flips correctly, but currentIndex
  -- jumps from 0 to 2, skipping the required index 1.
  -- expectedCi = (0 + 1) mod 2 = 1, so ci' = 2 /= 1 triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2 -- wrong: should be (0 + 1) mod 2 = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: currentIndex does not advance on Hit (stays the same)
--
-- 2-player game: [Alice, Bob]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: currentIndex = 0 — index was not incremented at all.
-- validateHit check: ci' must equal (ci + 1) mod listLength players.
-- expectedCi = (0 + 1) mod 2 = 1, but ci' = 0, so the guard fires and the
-- validator must traceError "currentIndex did not advance correctly".
-- A player cannot 'pass' their turn; the index must always move forward.
-- ballState flips correctly (Pinged → Ponged) and all other fields are
-- correctly formed to isolate the index check exclusively.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
indexNoAdvanceTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
indexNoAdvanceTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, ballState flips correctly, but currentIndex
  -- remains 0 instead of advancing to 1.
  -- expectedCi = (0 + 1) mod 2 = 1, so ci' = 0 /= 1 triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0 -- wrong: should be (0 + 1) mod 2 = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: roundCount increments when it should not on Hit
--
-- 3-player game: [Alice, Bob, Carol]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: currentIndex = 1 (correct), but roundCount = 1 instead of 0.
-- validateHit check: roundCount increment is only valid when expectedCi == 0
-- (i.e. the index wraps back to the start of the list).
-- expectedCi = (0 + 1) mod 3 = 1, which is /= 0, so rc' must equal rc.
-- rc' = 1 /= rc = 0, so the guard fires and the validator must traceError
-- "roundCount must not change unless index wraps".
-- ballState flips correctly (Pinged → Ponged) and all other fields are
-- correctly formed to isolate the roundCount check exclusively.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
roundCountSpuriousIncrementTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
roundCountSpuriousIncrementTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, ballState flips correctly, index advances
  -- correctly (0 → 1), but roundCount is incorrectly incremented to 1.
  -- expectedCi = (0 + 1) mod 3 = 1 /= 0, so no wrap occurred and rc'
  -- must equal rc = 0. rc' = 1 /= 0 triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 1 -- wrong: should be 0 (no wrap at index 1)
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: roundCount stays unchanged when index wraps on Hit
--
-- 2-player game: [Alice, Bob]
-- Input datum: Ponged, currentIndex = 1 (Bob's turn). Bob signs (correct player).
-- Output datum: currentIndex = 0 (correct wrap), but roundCount = 0 unchanged.
-- validateHit check: when expectedCi == 0 (wrap occurred), rc' must equal rc + 1.
-- expectedCi = (1 + 1) mod 2 = 0, so rc' must be rc + 1 = 1.
-- rc' = 0 == rc = 0, so rc' /= rc + 1, the guard fires and the validator must
-- traceError "roundCount must not change unless index wraps".
-- ballState flips correctly (Ponged → Pinged) and all other fields are
-- correctly formed to isolate the roundCount check exclusively.
-- The datum is locked directly at the pre-wrap state to avoid setup hits.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
roundCountNoIncrementOnWrapTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
roundCountNoIncrementOnWrapTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Ponged, currentIndex = 1 (Bob's turn), active, roundCount 0.
  -- This is the state the game would be in after Alice's first hit
  -- (Pinged → Ponged, index 0 → 1). Locked directly to skip the setup hit.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Bob signs correctly, ballState flips correctly (Ponged → Pinged),
  -- index wraps correctly (1 → 0), but roundCount stays at 0 instead of
  -- incrementing to 1.
  -- expectedCi = (1 + 1) mod 2 = 0, so the wrap path is taken and rc' must
  -- equal rc + 1 = 1. rc' = 0 /= 1 triggers the guard.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0 -- wrong: should be rc + 1 = 1 (wrap occurred)
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty bob hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: players list modified in output datum on Hit
--
-- 2-player game: [Alice, Bob]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: players = [Alice] — Bob was removed from the list.
-- validateHit check: players' must equal players (roster must not change).
-- The guard fires and the validator must traceError
-- "players list must not change".
-- All other fields (currentIndex, ballState, roundCount, active) are
-- correctly formed to isolate the players check exclusively.
-- Prevents mid-game roster changes.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
playersListModifiedTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
playersListModifiedTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly, all state fields advance correctly, but the
  -- output players list is [Alice] only — Bob has been removed.
  -- ps' = [Alice's PKH] /= ps = [Alice's PKH, Bob's PKH], so the guard fires.
  -- -------------------------------------------------------------------------

  let ps' = [transPubKeyHash (verificationKeyHash alice)] -- Bob removed
  let outputDatum =
        MultiPingPongDatum
          { players = ps' -- wrong: must equal the input players list
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: active flag set to False in output datum on Hit
--
-- 2-player game: [Alice, Bob]
-- Input datum: Pinged, currentIndex = 0. Alice signs (correct player).
-- Output datum: active = False.
-- validateHit check: active' must remain True after Hit.
-- The guard fires and the validator must traceError
-- "active must remain True after Hit".
-- All other fields (players, currentIndex, ballState, roundCount) are
-- correctly formed to isolate the active check exclusively.
-- You cannot use Hit to stop the game; only Stop can transition to inactive.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
activeSetFalseOnHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
activeSetFalseOnHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 0 (Alice's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs correctly; players, ballState, currentIndex, and
  -- roundCount are all correct, but active is incorrectly set to False.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = False -- wrong: must stay True on Hit
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: output datum has invalid currentIndex (out of bounds)
--
-- 3-player game: [Alice, Bob, Carol]
-- Input datum: Pinged, currentIndex = 2 (Carol's turn). Carol signs.
-- Output datum: currentIndex = 3 (equal to numPlayers, therefore invalid).
-- This models a bogus post-Hit datum where the turn index leaves the valid
-- range [0 .. numPlayers-1]. validateDatum on the output datum must reject.
-- Confirms output datum is revalidated and cannot introduce invalid indices.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
outputIndexOutOfBoundsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
outputIndexOutOfBoundsTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: Pinged, currentIndex = 2 (Carol's turn), active, roundCount 0.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Carol signs; players/ballState/roundCount/active are otherwise
  -- well-formed, but currentIndex = 3 is out of bounds for 3 players.
  -- validateDatum on the output datum must fail.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 3 -- invalid: must be in [0..2]
          , ballState = Ponged
          , roundCount = 1
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty carol hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: Hit submitted when game is not active
--
-- 2-player game: [Alice, Bob]
-- Input datum: active = False (game already stopped), currentIndex = 0.
-- Alice submits Hit with a otherwise-valid transition.
-- validateHit check 1: active must be True.
-- Since active = False, validator must traceError "game is not active".
-- A stopped game cannot be restarted via Hit; only Stop ends the game.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
hitWhenInactiveTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
hitWhenInactiveTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: inactive game (active = False), currentIndex = 0 (Alice's turn).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = False
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Hit: Alice signs and provides a normal-looking transition.
  -- Should still fail because input active = False.
  -- -------------------------------------------------------------------------

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- First player stops the game
--
-- 2-player game: [Alice, Bob]
-- Alice (players[0]) submits a Stop redeemer on an active game.
-- No continuation output is required after Stop.
-- Verifies: active check passes, anySignedBy succeeds for players[0].
-------------------------------------------------------------------------------
aliceStopTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
aliceStopTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn), Pinged, roundCount 0.
  -- The Stop redeemer does not care about turn order — any registered player
  -- may stop — but we use a fresh initial state for simplicity.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Alice signs. No continuation output needed.
  -- validateStop checks: (1) game is active, (2) signer is a registered player.
  -- Alice satisfies both. The funds are simply returned to Alice's wallet by
  -- the balancer since there is no script output to send them to.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty alice stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Non-current player stops the game
--
-- 2-player game: [Alice, Bob]
-- currentIndex = 0 (Alice's turn), but Bob signs the Stop redeemer.
-- validateStop uses anySignedBy, not players !! currentIndex, so Bob's
-- signature is sufficient even though it is not his turn.
-- Verifies: Stop is not gated on turn order.
-------------------------------------------------------------------------------
bobStopsOnAliceTurnTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
bobStopsOnAliceTurnTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- We intentionally do not advance the game — the point of this test is that
  -- Bob can stop it before Alice even takes her turn.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Bob signs even though currentIndex = 0 (Alice's turn).
  -- anySignedBy checks membership in the players list, not turn order.
  -- Bob is players[1], so the check passes.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty bob stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Last player in list stops the game
--
-- 3-player game: [Alice, Bob, Carol]
-- Carol is players[2], the last element in the list.
-- currentIndex = 0 (Alice's turn), Carol signs Stop.
-- anySignedBy must traverse the full list before finding Carol's PubKeyHash.
-- Ensures anySignedBy reaches the end of the list without short-circuiting.
-------------------------------------------------------------------------------
lastPlayerStopsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
lastPlayerStopsTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- We do not advance the game — Carol stops it immediately from its
  -- initial state, exercising the full anySignedBy traversal.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Carol signs. She is players[2], the last element in the list.
  -- anySignedBy must check Alice (no match), Bob (no match), then Carol
  -- (match) before returning True. Tests the full list traversal path.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty carol stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Stop accepted when game has many rounds played
--
-- 2-player game: [Alice, Bob]
-- The datum is locked directly with roundCount = 100, simulating a game that
-- has completed 100 full rotations. Alice signs Stop.
-- validateStop does not inspect roundCount at all — this test confirms that
-- a high roundCount has no effect on the Stop path.
-------------------------------------------------------------------------------
stopAfterManyRoundsTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
stopAfterManyRoundsTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game with roundCount = 100.
  -- We set this directly in the datum rather than playing 100 rounds, since
  -- the purpose of the test is the Stop path, not the Hit path.
  -- currentIndex = 0 and ballState = Pinged are consistent with having just
  -- completed a full rotation (the state the game would be in after any wrap).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 100
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Alice signs. validateStop only checks active and anySignedBy —
  -- it never reads roundCount. A value of 100 must not cause a failure.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty alice stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: outsider signs Stop (not in players list)
--
-- 2-player game: [Alice, Bob]
-- Carol (w3) signs the Stop redeemer. She is not in the players list.
-- validateStop check: anySignedBy ps signatories must be True.
-- signatories = [Carol's PKH].
-- Neither Alice nor Bob signed, so anySignedBy traverses the full list and
-- returns False. The validator must traceError
-- "Stop must be signed by a registered player".
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
outsiderStopTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
outsiderStopTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3 -- outsider: not in the players list
  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- Carol is intentionally absent from the players list.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Carol signs. She is not a registered player (absent from ps).
  -- anySignedBy checks Alice (no match) then Bob (no match) and returns False.
  -- The validator must reject the transaction.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty carol stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: nobody signs Stop (empty signatories)
--
-- 2-player game: [Alice, Bob]
-- No required signatory is declared in the Stop transaction.
-- validateStop check: anySignedBy ps signatories must be True.
-- signatories = [].
-- anySignedBy traverses the full players list and finds no match, returning
-- False. The validator must traceError
-- "Stop must be signed by a registered player".
-- Alice is used as the fee payer only — her key does not appear in
-- txInfoSignatories because it is not declared as a required signatory.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
noSignerStopTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noSignerStopTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: active game, currentIndex = 0 (Alice's turn).
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: no addRequiredSignature call, so txInfoSignatories = [].
  -- anySignedBy ps [] = False for any non-empty players list, so the
  -- validator must reject regardless of who submits the transaction.
  -- Alice is used as the fee payer only — her key does not appear in
  -- txInfoSignatories because it is not declared as a required signatory.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty alice stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: Stop submitted on an already-stopped game
--
-- 2-player game: [Alice, Bob]
-- The datum is locked directly with active = False, simulating a game that
-- has already been stopped.
-- validateStop check 1: active must be True.
-- active = False, so the validator must traceError "game is already stopped"
-- before even reaching the signer check.
-- Alice signs, so the signer check would pass — this isolates check 1 alone.
-- Prevents double-stopping a game.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
stopAlreadyStoppedTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
stopAlreadyStoppedTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- -------------------------------------------------------------------------
  -- Lock: inactive game (active = False).
  -- We set this directly in the datum to simulate a game that was already
  -- stopped, without needing to play through a real Stop transaction first.
  -- -------------------------------------------------------------------------

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = False
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- -------------------------------------------------------------------------
  -- Stop: Alice signs — she is a registered player, so the signer check
  -- would pass. The active check fires first and must reject the transaction.
  -- -------------------------------------------------------------------------

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty alice stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Accept: complete 2-player game trace (4 Hits, then Stop)
--
-- Players: [Alice, Bob]
-- Hit sequence: Alice, Bob, Alice, Bob
-- Then Alice submits Stop.
--
-- State trace:
--   S0: Pinged, idx 0, rc 0
--   S1: Ponged, idx 1, rc 0   (Alice hit)
--   S2: Pinged, idx 0, rc 1   (Bob hit, wrap)
--   S3: Ponged, idx 1, rc 1   (Alice hit)
--   S4: Pinged, idx 0, rc 2   (Bob hit, wrap)
-- Stop is executed from S4, so final pre-Stop roundCount is verified as 2.
-- Each script output UTxO is consumed as the next transaction input.
-------------------------------------------------------------------------------
completeTwoPlayerGameFourHitsThenStopTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
completeTwoPlayerGameFourHitsThenStopTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- S0: initial state
  let s0 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s0
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []
  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- Hit 1 (Alice): S0 -> S1
  let s1 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hit1Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s1
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice hit1Tx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- Hit 2 (Bob): S1 -> S2 (wrap, rc increments)
  let s2 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 1
          , active = True
          }

  let hit2Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s2
            C.NoStakeAddress
            lockedValue

  txId2 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob hit2Tx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- Hit 3 (Alice): S2 -> S3
  let s3 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 1
          , active = True
          }

  let hit3Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn2 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s3
            C.NoStakeAddress
            lockedValue

  txId3 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice hit3Tx TrailingChange []
  let txIn3 = C.TxIn txId3 (C.TxIx 0)

  -- Hit 4 (Bob): S3 -> S4 (wrap, rc increments to 2)
  let s4 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 2
          , active = True
          }

  let hit4Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn3 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s4
            C.NoStakeAddress
            lockedValue

  txId4 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob hit4Tx TrailingChange []
  let txIn4 = C.TxIn txId4 (C.TxIx 0)

  -- Stop from S4 (roundCount = 2) by Alice
  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn4 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty alice stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Accept: complete 3-player game trace (one full rotation, then Stop)
--
-- Players: [Alice, Bob, Carol]
-- Hit sequence: Alice, Bob, Carol
-- Then Bob submits Stop.
--
-- State trace:
--   S0: Pinged, idx 0, rc 0
--   S1: Ponged, idx 1, rc 0   (Alice hit)
--   S2: Pinged, idx 2, rc 0   (Bob hit)
--   S3: Ponged, idx 0, rc 1   (Carol hit, wrap)
-- Stop is executed from S3, so final pre-Stop roundCount is verified as 1.
-- Each script output UTxO is consumed as the next transaction input.
-------------------------------------------------------------------------------
completeThreePlayerFullRotationThenStopTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
completeThreePlayerFullRotationThenStopTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  -- S0: initial state
  let s0 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s0
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []
  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  -- Hit 1 (Alice): S0 -> S1
  let s1 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hit1Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s1
            C.NoStakeAddress
            lockedValue

  txId1 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice hit1Tx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- Hit 2 (Bob): S1 -> S2
  let s2 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 2
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let hit2Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn1 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s2
            C.NoStakeAddress
            lockedValue

  txId2 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty bob hit2Tx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0)

  -- Hit 3 (Carol): S2 -> S3 (wrap, rc increments to 1)
  let s3 =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Ponged
          , roundCount = 1
          , active = True
          }

  let hit3Tx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash carol)
          BuildTx.spendPlutusInlineDatum txIn2 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s3
            C.NoStakeAddress
            lockedValue

  txId3 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty carol hit3Tx TrailingChange []
  let txIn3 = C.TxIn txId3 (C.TxIx 0)

  -- Stop from S3 (roundCount = 1) by Bob
  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash bob)
          BuildTx.spendPlutusInlineDatum txIn3 validatorScript Stop

  _ <- tryBalanceAndSubmit mempty bob stopTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Reject: replay the same script input UTxO twice
--
-- 2-player game: [Alice, Bob]
-- A valid Hit is submitted once and succeeds.
-- The exact same Hit transaction is then submitted again, attempting to spend
-- the already-consumed input UTxO.
-- The second submission must fail due to ledger double-spend prevention.
-- This is a ledger-level invariant, not a validator-level guard.
-- The caller is expected to wrap this in mockchainFails.
-------------------------------------------------------------------------------
replaySameUtxoHitTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
replaySameUtxoHitTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  let initialDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            initialDatum
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []

  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  let outputDatum =
        MultiPingPongDatum
          { players = ps
          , currentIndex = 1
          , ballState = Ponged
          , roundCount = 0
          , active = True
          }

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash alice)
          BuildTx.spendPlutusInlineDatum txIn0 validatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            outputDatum
            C.NoStakeAddress
            lockedValue

  -- First spend: valid and succeeds
  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  -- Second spend: must fail (input UTxO already consumed)
  _ <- tryBalanceAndSubmit mempty alice hitTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Accept: 5-player game reaches roundCount = 3 after 15 hits (3 full rotations)
--
-- Players: [Alice, Bob, Carol, Dave, Eve]
-- Hit sequence: (Alice, Bob, Carol, Dave, Eve) repeated 3 times = 15 hits.
-- Verifies the property for complete rounds:
--   roundCount = totalHits / numPlayers = 15 / 5 = 3
-- We construct and submit each intermediate output datum in sequence, where
-- every script output UTxO is consumed by the next Hit transaction.
-------------------------------------------------------------------------------
fivePlayerThreeRotationsRoundCountTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
fivePlayerThreeRotationsRoundCountTest = do
  let alice = MockWallet.w1
      bob = MockWallet.w2
      carol = MockWallet.w3
      dave = MockWallet.w4
      eve = MockWallet.w5

  let ps =
        [ transPubKeyHash (verificationKeyHash alice)
        , transPubKeyHash (verificationKeyHash bob)
        , transPubKeyHash (verificationKeyHash carol)
        , transPubKeyHash (verificationKeyHash dave)
        , transPubKeyHash (verificationKeyHash eve)
        ]

  let validatorScript = multiPlayerPingPongValidatorScript
      validator = C.PlutusScript C.plutusScriptVersion validatorScript
      scriptHash = C.hashScript validator

  let lockedValue = C.lovelaceToValue 2_000_000

  let mkDatum ci bs rc =
        MultiPingPongDatum
          { players = ps
          , currentIndex = ci
          , ballState = bs
          , roundCount = rc
          , active = True
          }

  -- S0
  let s0 = mkDatum 0 Pinged 0

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            scriptHash
            s0
            C.NoStakeAddress
            lockedValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId0 <-
    C.getTxId . C.getTxBody
      <$> tryBalanceAndSubmit mempty alice lockTx TrailingChange []
  let txIn0 = C.TxIn txId0 (C.TxIx 0)

  let hitters =
        [ alice
        , bob
        , carol
        , dave
        , eve
        , alice
        , bob
        , carol
        , dave
        , eve
        , alice
        , bob
        , carol
        , dave
        , eve
        ]

  let submitHit txIn step signer = do
        let k = toInteger step
            ci = k `mod` 5
            rc = k `div` 5
            bs = if odd step then Ponged else Pinged
            outDatum = mkDatum ci bs rc

        let hitTx =
              execBuildTx $ do
                BuildTx.addRequiredSignature (verificationKeyHash signer)
                BuildTx.spendPlutusInlineDatum txIn validatorScript Hit
                BuildTx.payToScriptInlineDatum
                  Defaults.networkId
                  scriptHash
                  outDatum
                  C.NoStakeAddress
                  lockedValue

        txId <-
          C.getTxId . C.getTxBody
            <$> tryBalanceAndSubmit mempty signer hitTx TrailingChange []
        return (C.TxIn txId (C.TxIx 0))

  let runHits _ _ [] = pure ()
      runHits txIn step (s : ss) = do
        txIn' <- submitHit txIn step s
        runHits txIn' (step + 1) ss

  -- Executes 15 valid hits; final datum is:
  -- currentIndex = 0, ballState = Ponged, roundCount = 3, active = True.
  runHits txIn0 (1 :: Int) hitters

  return ()
