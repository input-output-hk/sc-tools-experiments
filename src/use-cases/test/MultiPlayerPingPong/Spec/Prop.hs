{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module MultiPlayerPingPong.Spec.Prop (
  propBasedTests,
) where

import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Control.Monad (void, when)
import Control.Monad.Except (MonadError, runExceptT)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (utxoSet)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (TestingInterface (..), propRunActions)
import Convex.ThreatModel.DatumBloat (datumListBloatAttack)
import Convex.ThreatModel.DuplicateListEntry (duplicateListEntryAttack)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
import Convex.ThreatModel.LargeValue (largeValueAttackWith)
import Convex.ThreatModel.MutualExclusion (mutualExclusionAttack)
import Convex.ThreatModel.NegativeInteger (negativeIntegerAttack)
import Convex.ThreatModel.SignatoryRemoval (signatoryRemoval)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.ThreatModel.TokenForgery (simpleAlwaysSucceedsMintingPolicyV2, simpleTestAssetName, tokenForgeryAttack)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utxos (toApiUtxo)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import GHC.Generics (Generic)
import MultiPlayerPingPong.Scripts (multiPlayerPingPongValidatorScript)
import MultiPlayerPingPong.Validator (BallState (Pinged, Ponged), MultiPingPongDatum (..), MultiRedeemer (Hit, Stop))
import PlutusLedgerApi.V1.Crypto (PubKeyHash)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck qualified as QC

-------------------------------------------------------------------------------
-- Property-based tests for MultiPlayerPingPong validator
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ propRunActions @MultiPlayerPingPongModel "Property-based test multi-player ping-pong validator"
    ]

-------------------------------------------------------------------------------
-- MultiPlayerPingPong Testing Interface
-------------------------------------------------------------------------------

{- | Model of the MultiPlayerPingPong contract state for property-based testing.

  Configuration:
  - Players: [w1, w2, w3]
  - Initial state: Pinged
  - Initial currentIndex: 0
  - Initial roundCount: 0
  - Locked value: 2 ADA
-}
data MultiPlayerPingPongModel = MultiPlayerPingPongModel
  { _players :: [Wallet]
  -- ^ Ordered participant list.
  , _currentIndex :: Integer
  -- ^ Index of the player who must sign the next Hit.
  , _ballState :: BallState
  -- ^ Current ball state.
  , _roundCount :: Integer
  -- ^ Number of completed full rotations.
  , _active :: Bool
  -- ^ Whether game is still active.
  , _initialized :: Bool
  -- ^ Whether script UTxO has been created.
  , _curSlot :: C.SlotNo
  -- ^ Current slot.
  , _lockedValue :: C.Lovelace
  -- ^ Value locked in script UTxO.
  }
  deriving (Show, Eq, Generic)

instance TestingInterface MultiPlayerPingPongModel where
  data Action MultiPlayerPingPongModel
    = PrepareGame
    | -- \^ Lock initial MultiPingPongDatum at validator address.
      HitTurn
    | -- \^ A valid player performs a Hit transition.
      HitTurnAs Wallet
    | -- \^ Any player performs a Hit transition (valid or not).
      StopGame Wallet
    | -- \^ A player stops the game (valid or not).
      WaitSlots C.SlotNo
    -- \^ Advance blockchain time.
    deriving (Show, Eq)

  -- \| Initial model state.
  initialState =
    MultiPlayerPingPongModel
      { _players = [MockWallet.w1, MockWallet.w2, MockWallet.w3]
      , _currentIndex = 0
      , _ballState = Pinged
      , _roundCount = 0
      , _active = True
      , _initialized = False
      , _curSlot = 0
      , _lockedValue = 2_000_000
      }

  -- \| Generate random actions weighted by current state.
  arbitraryAction m =
    QC.frequency
      [ (prepareWeight, pure PrepareGame)
      , (hitWeight, pure HitTurn)
      , (hitAsWeight, genHitAs)
      , (stopWeight, genStop)
      , (waitWeight, genWait)
      ]
   where
    prepareWeight = if _initialized m then 0 else 10
    hitWeight =
      if not (_initialized m) || not (_active m)
        then 0
        else 8
    hitAsWeight =
      if not (_initialized m) || not (_active m)
        then 0
        else 4
    stopWeight =
      if not (_initialized m) || not (_active m)
        then 0
        else 2
    waitWeight = 3

    genWait = do
      slots <- C.SlotNo <$> Gen.chooseWord64 (1, 20)
      pure $ WaitSlots slots

    genHitAs = HitTurnAs <$> Gen.elements allWallets

    genStop = StopGame <$> Gen.elements allWallets

  -- \| Preconditions determine which actions are valid in current state.
  precondition m PrepareGame = not (_initialized m)
  precondition m HitTurn = _initialized m && _active m
  precondition m (HitTurnAs w) = _initialized m && _active m && w == walletAtIndex (_players m) (_currentIndex m)
  precondition m (StopGame w) = _initialized m && _active m && w `elem` _players m
  precondition _ (WaitSlots _) = True

  -- \| nextState updates the model based on actions.
  nextState m PrepareGame =
    m
      { _initialized = True
      , _curSlot = _curSlot m + 1
      }
  nextState m HitTurn =
    m
      { _currentIndex = nextIx
      , _ballState = flipBallState (_ballState m)
      , _roundCount = nextRounds
      , _curSlot = _curSlot m + 1
      }
   where
    n = fromIntegral (length (_players m))
    nextIx = (_currentIndex m + 1) `mod` n
    nextRounds = if nextIx == 0 then _roundCount m + 1 else _roundCount m
  nextState m (HitTurnAs _) = nextState m HitTurn
  nextState m (StopGame _) =
    m
      { _active = False
      , _curSlot = _curSlot m + 1
      }
  nextState m (WaitSlots slots) =
    m
      { _curSlot = _curSlot m + slots
      }

  -- \| perform executes actions on the mockchain.
  perform m PrepareGame = do
    -- C.liftIO $ putStrLn "Performing PrepareGame action"

    runExceptT (prepareGamePBT (_players m) (_lockedValue m))
      >>= \case
        Left err -> fail $ "PrepareGame failed: " <> show err
        Right _ -> pure ()
  perform m HitTurn = do
    let currentPlayer = walletAtIndex (_players m) (_currentIndex m)

    -- C.liftIO $ putStrLn $ "Performing HitTurn for player index " <> show (_currentIndex m) <> " with state " <> show (_ballState m) <> " and round " <> show (_roundCount m)

    if not (_initialized m) || not (_active m)
      then fail "HitTurn not allowed in current state"
      else
        runExceptT
          ( hitTurnAsPBT
              (_players m)
              (_currentIndex m)
              (_ballState m)
              (_roundCount m)
              currentPlayer
              (_curSlot m)
              (_lockedValue m)
          )
          >>= \case
            Left err -> fail $ "HitTurn failed: " <> show err
            Right _ -> pure ()
  perform m (HitTurnAs w) = do
    -- C.liftIO $ putStrLn $ "Performing HitTurnAs for wallet " <> show (playerPkh w)

    if not (_initialized m) || not (_active m)
      then fail "HitTurnAs not allowed in current state"
      else
        runExceptT
          ( hitTurnAsPBT
              (_players m)
              (_currentIndex m)
              (_ballState m)
              (_roundCount m)
              w
              (_curSlot m)
              (_lockedValue m)
          )
          >>= \case
            Left err -> fail $ "HitTurnAs failed: " <> show err
            Right _ -> pure ()
  perform m (StopGame w) = do
    -- C.liftIO $ putStrLn $ "Performing StopGame with signer " <> show (playerPkh w)

    if not (_initialized m) || not (_active m)
      then fail "StopGame not allowed in current state"
      else
        runExceptT
          ( stopGamePBT
              (_players m)
              w
              (_curSlot m)
          )
          >>= \case
            Left err -> fail $ "StopGame failed: " <> show err
            Right _ -> pure ()
  perform _ (WaitSlots _) = pure ()

  validate _ = pure True

  threatModels =
    [ datumListBloatAttack
    , duplicateListEntryAttack
    , largeDataAttackWith 10
    , largeValueAttackWith 10
    , mutualExclusionAttack
    , negativeIntegerAttack
    , signatoryRemoval
    , unprotectedScriptOutput
    ]

  expectedVulnerabilities =
    [ timeBoundManipulation
    , tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName
    ]

  monitoring _ _ = error "monitoring not implemented"

-------------------------------------------------------------------------------
-- Helper functions for the model
-------------------------------------------------------------------------------

validatorScriptHash :: C.ScriptHash
validatorScriptHash =
  C.hashScript $ C.PlutusScript C.plutusScriptVersion multiPlayerPingPongValidatorScript

playerPkh :: Wallet -> PubKeyHash
playerPkh = transPubKeyHash . verificationKeyHash

modelPlayersDatum :: [Wallet] -> [PubKeyHash]
modelPlayersDatum = map playerPkh

allWallets :: [Wallet]
allWallets = [MockWallet.w1, MockWallet.w2, MockWallet.w3, MockWallet.w4, MockWallet.w5, MockWallet.w6]

walletAtIndex :: [Wallet] -> Integer -> Wallet
walletAtIndex ws ix = ws !! fromIntegral ix

flipBallState :: BallState -> BallState
flipBallState Pinged = Ponged
flipBallState Ponged = Pinged

-------------------------------------------------------------------------------
-- Property-Based Testing functions
-------------------------------------------------------------------------------

-- | Prepare game by locking initial datum at script address.
prepareGamePBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => [Wallet]
  -> C.Lovelace
  -> m ()
prepareGamePBT ws lockedValue = do
  let initialDatum =
        MultiPingPongDatum
          { players = modelPlayersDatum ws
          , currentIndex = 0
          , ballState = Pinged
          , roundCount = 0
          , active = True
          }

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            validatorScriptHash
            initialDatum
            C.NoStakeAddress
            (C.lovelaceToValue lockedValue)
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  void $ tryBalanceAndSubmit mempty (head ws) lockTx TrailingChange []

-- | Perform a valid Hit transition signed by the current player.
hitTurnAsPBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => [Wallet]
  -> Integer
  -> BallState
  -> Integer
  -> Wallet
  -> C.SlotNo
  -> C.Lovelace
  -> m ()
hitTurnAsPBT ws currentIx currentBall currentRounds signer curSlot lockedValue = do
  scriptUtxos <- utxosAt @C.ConwayEra validatorScriptHash
  when (null scriptUtxos) $ fail "No MultiPlayerPingPong script UTxO found"

  let (txIn, _) = head scriptUtxos
      playerCount = fromIntegral (length ws)
      nextIx = (currentIx + 1) `mod` playerCount
      nextRounds = if nextIx == 0 then currentRounds + 1 else currentRounds
      outDatum =
        MultiPingPongDatum
          { players = modelPlayersDatum ws
          , currentIndex = nextIx
          , ballState = flipBallState currentBall
          , roundCount = nextRounds
          , active = True
          }

  setSlot curSlot

  let hitTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash signer)
          BuildTx.spendPlutusInlineDatum txIn multiPlayerPingPongValidatorScript Hit
          BuildTx.payToScriptInlineDatum
            Defaults.networkId
            validatorScriptHash
            outDatum
            C.NoStakeAddress
            (C.lovelaceToValue lockedValue)

  _ <- tryBalanceAndSubmit mempty signer hitTx TrailingChange []
  pure ()

-- | Stop the game signed by a registered player.
stopGamePBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => [Wallet]
  -> Wallet
  -> C.SlotNo
  -> m ()
stopGamePBT _ws signer curSlot = do
  scriptUtxos <- utxosAt @C.ConwayEra validatorScriptHash
  when (null scriptUtxos) $ fail "No MultiPlayerPingPong script UTxO found"

  let (txIn, _) = head scriptUtxos

  setSlot curSlot

  let stopTx =
        execBuildTx $ do
          BuildTx.addRequiredSignature (verificationKeyHash signer)
          BuildTx.spendPlutusInlineDatum txIn multiPlayerPingPongValidatorScript Stop

  _ <- tryBalanceAndSubmit mempty signer stopTx TrailingChange []
  pure ()

-- | Fetch UTxOs at the validator script address.
utxosAt
  :: forall era m
   . (MonadMockchain era m, MonadFail m, C.IsBabbageBasedEra era)
  => C.ScriptHash
  -> m [(C.TxIn, C.TxOut C.CtxUTxO era)]
utxosAt scriptHash = do
  utxos <- utxoSet
  let scriptUtxos =
        [ (txIn, txOut)
        | (txIn, txOut@(C.TxOut addr _ _ _)) <- C.UTxO.toList (toApiUtxo utxos)
        , isScriptAddress addr
        ]
  pure scriptUtxos
 where
  isScriptAddress (C.AddressInEra _ (C.ShelleyAddress _ (ScriptHashObj h) _)) =
    h == C.toShelleyScriptHash scriptHash
  isScriptAddress _ = False
