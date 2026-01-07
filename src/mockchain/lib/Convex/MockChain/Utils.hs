{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}

-- | Utility functions for using the mockchain types in @hunit@ or @QuickCheck@ tests
module Convex.MockChain.Utils (
  -- * Useful mockchain actions

  -- * Running mockchain actions in HUnit tests
  mockchainSucceeds,
  mockchainSucceedsWith,
  mockchainSucceedsWithOptions,
  mockchainFails,
  mockchainFailsWith,
  mockchainFailsWithOptions,

  -- * Running mockchain actions in QuickCheck tests
  runMockchainProp,
  runMockchainPropWith,
  runTestableErr,

  -- * Options for running mockchain testCase
  Options (..),
  defaultOptions,
) where

import Cardano.Api (ConwayEra)
import Cardano.Api qualified as C
import Control.Exception (SomeException, try)
import Control.Lens ((^.))
import Control.Monad.Except (ExceptT, runExceptT)
import Control.Monad.IO.Class (liftIO)
import Convex.Class (coverageData)
import Convex.MockChain (
  InitialUTXOs,
  MockchainIO,
  MockchainT,
  initialStateFor,
  runMockchain,
  runMockchain0IOWith,
 )
import Convex.MockChain.Defaults qualified as Defaults
import Convex.NodeParams (NodeParams)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Functor.Identity (Identity)
import Data.IORef (IORef, modifyIORef)
import PlutusTx.Coverage (CoverageData)
import Test.HUnit (Assertion)
import Test.QuickCheck (
  Property,
  Testable (..),
  counterexample,
 )
import Test.QuickCheck.Monadic (PropertyM (..), monadic, monadicIO)

data Options era = Options
  { params :: NodeParams era
  , coverageRef :: Maybe (IORef CoverageData)
  }

defaultOptions :: Options ConwayEra
defaultOptions =
  Options
    { params = Defaults.nodeParams
    , coverageRef = Nothing
    }

-- | Run the 'Mockchain' action and fail if there is an error
mockchainSucceeds :: MockchainIO C.ConwayEra a -> Assertion
mockchainSucceeds = mockchainSucceedsWith Defaults.nodeParams

-- | Run the 'Mockchain' action with the given node parameters and fail if there is an error
mockchainSucceedsWith :: (C.IsShelleyBasedEra era) => NodeParams era -> MockchainIO era a -> Assertion
mockchainSucceedsWith params = mockchainSucceedsWithOptions Options{params, coverageRef = Nothing}

-- | Run the 'Mockchain' action with the given options and fail if there is an error
mockchainSucceedsWithOptions :: (C.IsShelleyBasedEra era) => Options era -> MockchainIO era a -> Assertion
mockchainSucceedsWithOptions Options{params, coverageRef} action =
  try @SomeException (runMockchain0IOWith Wallet.initialUTxOs params action) >>= \case
    Right (_, st) -> do
      case coverageRef of
        Nothing -> pure ()
        Just ref -> do
          let covData = st ^. coverageData
          modifyIORef ref (<> covData)
      pure ()
    Left err -> fail (show err)

{- | Run the 'Mockchain' action, fail if it succeeds, and handle the error
  appropriately.
-}
mockchainFails :: MockchainIO C.ConwayEra a -> (SomeException -> Assertion) -> Assertion
mockchainFails =
  mockchainFailsWith Defaults.nodeParams

{- | Run the 'Mockchain' action with the given node parameters, fail if it
    succeeds, and handle the error appropriately.
-}
mockchainFailsWith :: (C.IsShelleyBasedEra era) => NodeParams era -> MockchainIO era a -> (SomeException -> Assertion) -> Assertion
mockchainFailsWith params = mockchainFailsWithOptions Options{params, coverageRef = Nothing}

{- | Run the 'Mockchain' action with the given options, fail if it
    succeeds, and handle the error appropriately.
-}
mockchainFailsWithOptions :: (C.IsShelleyBasedEra era) => Options era -> MockchainIO era a -> (SomeException -> Assertion) -> Assertion
mockchainFailsWithOptions Options{params, coverageRef} action handleError =
  try @SomeException (runMockchain0IOWith Wallet.initialUTxOs params action) >>= \case
    Right (_, st) -> do
      case coverageRef of
        Nothing -> pure ()
        Just ref -> do
          let covData = st ^. coverageData
          modifyIORef ref (<> covData)
      fail "mockchainFailsWithOptions: Did not fail"
    Left err -> handleError err

{- | Run the 'Mockchain' action as a QuickCheck property, considering all 'MockchainError'
as test failures.
-}
runMockchainPropWith
  :: forall era a
   . (Testable a, C.IsShelleyBasedEra era)
  => NodeParams era
  -- ^ Node parameters to use for the mockchain
  -> InitialUTXOs
  -- ^ Initial distribution
  -> PropertyM (MockchainT era Identity) a
  -- ^ The mockchain action to run
  -> Property
runMockchainPropWith nodeParams =
  runMockchainPropWithOptions Options{params = nodeParams, coverageRef = Nothing}

{- | Run the 'Mockchain' action as a QuickCheck property, considering all 'MockchainError'
as test failures, with options.
}
-}
runMockchainPropWithOptions
  :: forall era a
   . (Testable a, C.IsShelleyBasedEra era)
  => Options era
  -- ^ Node parameters to use for the mockchain
  -> InitialUTXOs
  -- ^ Initial distribution
  -> PropertyM (MockchainT era Identity) a
  -- ^ The mockchain action to run
  -> Property
runMockchainPropWithOptions Options{params, coverageRef} utxos =
  monadic runFinalPredicate
 where
  runFinalPredicate
    :: MockchainT era Identity Property
    -> Property
  runFinalPredicate m =
    let (prop', state) = runMockchain m params iState
     in case coverageRef of
          Nothing -> prop'
          Just ref -> monadicIO $ do
            liftIO $ do
              let covData = state ^. coverageData
              modifyIORef ref (<> covData)
            pure prop'
  iState = initialStateFor params utxos

{- | Run the 'Mockchain' action as a QuickCheck property, using the default node params
    and initial distribution, and considering all 'MockchainError's as test failures.
-}
runMockchainProp :: forall a. (Testable a) => PropertyM (MockchainT C.ConwayEra Identity) a -> Property
runMockchainProp = runMockchainPropWith Defaults.nodeParams Wallet.initialUTxOs

-- | 'Either' with a 'Testable' instance for the 'Left' case
newtype TestableErr e a = TestableErr (Either e a)

instance (Show e, Testable a) => Testable (TestableErr e a) where
  property (TestableErr v) = case v of
    Left err -> counterexample (show err) False
    Right k -> property k

{- | Run the 'Mockchain' action as a QuickCheck property, using the default node params
    and initial distribution, and considering all 'MockchainError's as test failures.
-}
runTestableErr :: forall e m a. (Functor m) => ExceptT e m a -> m (TestableErr e a)
runTestableErr = fmap TestableErr . runExceptT
