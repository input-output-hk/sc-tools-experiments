{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Convex.TestingInterface (
  -- * testing interface
  TestingInterface (..),
  ModelState,

  -- * Running Tests
  propRunActions,
  propRunActionsWithOptions,
  RunOptions (..),
  defaultRunOptions,

  -- * Actions
  Actions (Actions),

  -- * Re-exports from QuickCheck
  Gen,
  Arbitrary (..),
  frequency,
  oneof,
  elements,
) where

import Control.Monad (foldM)
import Control.Monad.IO.Class (liftIO)
import Test.QuickCheck (Arbitrary (..), Gen, Property, conjoin, counterexample, elements, frequency, oneof, property)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)

import Cardano.Api qualified as C
import Convex.Class (getTxs, getUtxo)
import Convex.MockChain (MockChainState (MockChainState, mcsCoverageData), MockchainT, fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.Utils (Options (Options, coverageRef, params), defaultOptions)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Foldable (traverse_)
import Data.IORef (modifyIORef)

import Control.Lens ((^.))
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.ThreatModel (ThreatModel, ThreatModelEnv (..), runThreatModel)

{- | A testing interface defines the state and behavior of one or more smart contracts.

The type parameter @state@ represents the model's view of the world. It should
track all relevant information needed to validate that the contract is behaving
correctly.

Minimal complete definition: 'Action', 'initialState', 'arbitraryAction', 'nextState', 'perform'
-}
class (Show state, Eq state) => TestingInterface state where
  {- | Actions that can be performed on the contract.
  This is typically a data type with one constructor per contract operation.
  -}
  data Action state

  -- | The initial state of the model, before any actions are performed.
  initialState :: state

  {- | Generate a random action given the current state.
  The generated action should be appropriate for the current state.
  -}
  arbitraryAction :: state -> Gen (Action state)

  {- | Precondition that must hold before an action can be executed.
  Return 'False' to indicate that an action is not valid in the current state.
  Default: all actions are always valid.
  -}
  precondition :: state -> Action state -> Bool
  precondition _ _ = True

  {- | Update the model state after an action is performed.
  This should reflect the expected effect of the action on the contract state.
  -}
  nextState :: state -> Action state -> state

  {- | Perform the action on the real blockchain (mockchain).
  This should execute the actual transaction(s) that implement the action.
  The current model state is provided to allow access to tracked blockchain state.
  -}
  perform :: state -> Action state -> MockchainT C.ConwayEra IO ()

  {- | Validate that the blockchain state matches the model state.
  Default: no validation (always succeeds).
  -}
  validate :: state -> MockchainT C.ConwayEra IO Bool
  validate _ = pure True

  {- | Called after each action to check custom properties.
  Default: no additional checks.
  -}
  monitoring :: state -> Action state -> Property -> Property
  monitoring _ _ = id

  {- | Threat models to run against the last transaction.
  Each threat model will be evaluated against the final transaction
  with the UTxO state captured before that transaction executed.
  Default: no threat models.
  -}
  threatModels :: [ThreatModel ()]
  threatModels = []

-- | Opaque wrapper for model state
newtype ModelState state = ModelState {unModelState :: state}
  deriving (Eq, Show)

-- | A sequence of actions to perform
newtype Actions state = Actions_ [Action state]

pattern Actions :: [Action state] -> Actions state
pattern Actions as = Actions_ as
{-# COMPLETE Actions #-}

instance (TestingInterface state, Show (Action state)) => Show (Actions state) where
  show (Actions acts) = "Actions " ++ show acts

instance (TestingInterface state) => Arbitrary (Actions state) where
  arbitrary = Actions <$> genActions initialState 10

-- | Generate a list of valid actions
genActions :: (TestingInterface state) => state -> Int -> Gen [Action state]
genActions _ 0 = pure []
genActions s n = do
  maybeAction <- arbitraryAction s `suchThatMaybe` precondition s
  case maybeAction of
    Nothing -> pure [] -- Stop if no valid action can be generated
    Just action -> do
      let s' = nextState s action
      actions <- genActions s' (n - 1)
      pure (action : actions)
 where
  -- Try up to 100 times to generate a valid action, then give up
  suchThatMaybe gen p = go (100 :: Int)
   where
    go 0 = pure Nothing
    go retries = do
      a <- gen
      if p a then pure (Just a) else go (retries - 1)

-- | Options for running property tests
data RunOptions = RunOptions
  { verbose :: Bool
  -- ^ Print actions as they are executed
  , maxActions :: Int
  -- ^ Maximum number of actions to generate
  , mcOptions :: Options C.ConwayEra
  }

defaultRunOptions :: RunOptions
defaultRunOptions =
  RunOptions
    { verbose = False
    , maxActions = 10
    , mcOptions = defaultOptions
    }

{- | Main property for testing a testing interface.
Generates random action sequences and checks that the implementation matches the model.
-}
propRunActions :: (TestingInterface state, Show (Action state)) => Actions state -> Property
propRunActions = propRunActionsWithOptions defaultRunOptions

-- | Run testing interface tests with custom options
propRunActionsWithOptions
  :: forall state
   . (TestingInterface state, Show (Action state))
  => RunOptions
  -> Actions state
  -> Property
propRunActionsWithOptions opts@RunOptions{mcOptions = Options{coverageRef, params}} (Actions actions) = monadicIO $ do
  let initialSt = initialState @state

  when (verbose opts) $
    monitor (counterexample $ "Initial state: " ++ show initialSt)

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ do
    (finalState, lastUtxoBefore) <-
      foldM
        ( \(state, _) action -> do
            utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
            newState <- runAction opts state action
            pure (newState, Just utxoBefore)
        )
        (initialSt, Nothing)
        actions
    -- Get the last transaction
    allTxs <- getTxs
    let lastTx = if null allTxs then Nothing else Just (head allTxs)
    pure (finalState, lastUtxoBefore, lastTx)

  case result of
    ((finalState, lastUtxoBefore, lastTx), MockChainState{mcsCoverageData = covData}) -> do
      monitor (counterexample $ "Final state: " ++ show finalState)
      -- accumulate coverage
      traverse_ (\ref -> liftIO $ modifyIORef ref (<> covData)) coverageRef

      -- Run threat models if we have a transaction and UTxO
      case (lastTx, lastUtxoBefore) of
        (Just tx, Just utxo) -> do
          let pparams' = params ^. ledgerProtocolParameters
              env = ThreatModelEnv tx utxo pparams'
          pure $ conjoin [runThreatModel tm [env] | tm <- threatModels @state]
        _ -> pure (property True)
 where
  when True m = m
  when False _ = return ()

-- | Execute a single action and update the model state
runAction
  :: (TestingInterface state, Show (Action state))
  => RunOptions
  -> state
  -> Action state
  -> MockchainT C.ConwayEra IO state
runAction opts modelState action = do
  when (verbose opts) $
    liftIO $
      putStrLn $
        "Performing: " ++ show action

  -- Check precondition
  unless (precondition modelState action) $
    fail $
      "Precondition failed for action: " ++ show action

  -- Perform the action on the blockchain
  perform modelState action

  -- Update model state
  let modelState' = nextState modelState action

  -- Validate blockchain state matches model
  valid <- validate modelState'
  unless valid $
    fail "Blockchain state does not match model state"

  pure modelState'
 where
  unless True _ = pure ()
  unless False m = m
  when True m = m
  when False _ = pure ()
