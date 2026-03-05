{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Convex.TestingInterface (
  -- * Testing interface
  TestingInterface (..),
  ModelState,

  -- * Running Tests
  propRunActions,
  propRunActionsWithOptions,
  RunOptions (..),
  defaultRunOptions,

  -- * The Testing Monad
  TestingMonadT (..),
  mockchainSucceedsWithOptions,
  mockchainFailsWithOptions,
  Options (..),
  defaultOptions,
  modifyTransactionLimits,

  -- * Actions
  Actions (Actions),
  InvalidActions (..),

  -- * Coverage helpers
  withCoverage,
  CoverageConfig (..),
  printCoverageReport,
  writeCoverageReport,
  silentCoverageReport,
  printCoverageJSON,
  writeCoverageJSON,
  printCoverageJSONPretty,
  writeCoverageJSONPretty,
  CoverageSummary (..),
  coverageSummary,

  -- * Re-exports from QuickCheck
  Gen,
  Arbitrary (..),
  frequency,
  oneof,
  elements,

  -- * Re-exports from Tasty
  TestTree,
) where

import Control.Monad (foldM, forM, unless, when)
import Control.Monad.IO.Class (liftIO)
import Test.HUnit (Assertion)
import Test.QuickCheck (Arbitrary (..), Gen, Property, counterexample, discard, elements, frequency, oneof, property)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (DependencyType (..), TestTree, sequentialTestGroup, testGroup, withResource)
import Test.Tasty.ExpectedFailure (ignoreTestBecause)
import Test.Tasty.HUnit (assertFailure, testCaseSteps)
import Test.Tasty.QuickCheck (testProperty)

import Cardano.Api qualified as C
import Cardano.Ledger.Core qualified as L
import Control.Exception (SomeException, catch, throwIO, try)
import Control.Lens ((&), (.~), (^.))
import Convex.Class (MonadBlockchain, MonadMockchain, coverageData, getMockChainState, getTxs, getUtxo)
import Convex.CoinSelection (BalanceTxError, coverageFromBalanceTxError)
import Convex.MockChain (MockChainState (MockChainState, mcsCoverageData), MockchainT, fromLedgerUTxO, runMockchain0IOWith, runMockchainIO)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MonadLog (MonadLog)
import Convex.NodeParams (NodeParams (..), ledgerProtocolParameters)
import Convex.ThreatModel (ExceptT, ThreatModel, ThreatModelEnv (..), ThreatModelOutcome (..), getThreatModelName, runExceptT, runThreatModelCheck)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Aeson (ToJSON (..), (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Encode.Pretty qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.ByteString.Lazy.Char8 qualified as LBS
import Data.Foldable (foldl', for_, traverse_)
import Data.IORef (IORef, modifyIORef, newIORef, readIORef)
import Data.Map qualified as Map
import Data.Maybe (fromMaybe)
import Data.Set qualified as Set
import Data.Word (Word32)
import GHC.Generics (Generic)
import PlutusTx.Coverage (
  CovLoc (..),
  CoverageAnnotation (..),
  CoverageData,
  CoverageIndex,
  CoverageReport (..),
  Metadata (..),
  coverageAnnotations,
  coverageMetadata,
  coveredAnnotations,
  ignoredAnnotations,
  _metadataSet,
 )
import Prettyprinter qualified as Pretty
import System.Exit (ExitCode)

{- | A testing interface defines the state and behavior of one or more smart contracts.

The type parameter @state@ represents the model's view of the world. It should
track all relevant information needed to validate that the contract is behaving
correctly.

Minimal complete definition: 'Action', 'initialState', 'arbitraryAction', 'nextState', 'perform'
-}
class (Show state, Eq state) => TestingInterface state where
  -- | Actions that can be performed on the contract.
  --   This is typically a data type with one constructor per contract operation.
  data Action state

  -- | The initial state of the model, before any actions are performed.
  initialState :: state

  -- | Generate a random action given the current state.
  --   The generated action should be appropriate for the current state.
  arbitraryAction :: state -> Gen (Action state)

  -- | Precondition that must hold before an action can be executed.
  --   Return 'False' to indicate that an action is not valid in the current state.
  --   Default: all actions are always valid.
  precondition :: state -> Action state -> Bool
  precondition _ _ = True

  -- | Update the model state after an action is performed.
  --   This should reflect the expected effect of the action on the contract state.
  nextState :: state -> Action state -> state

  -- | Perform the action on the real blockchain (mockchain).
  --   This should execute the actual transaction(s) that implement the action.
  --   The current model state is provided to allow access to tracked blockchain state.
  perform :: state -> Action state -> TestingMonadT IO ()

  -- | Validate that the blockchain state matches the model state.
  --   Default: no validation (always succeeds).
  validate :: state -> TestingMonadT IO Bool
  validate _ = pure True

  -- | Called after each action to check custom properties.
  --   Default: no additional checks.
  monitoring :: state -> Action state -> Property -> Property
  monitoring _ _ = id

  -- | Threat models to run against the last transaction.
  --   Each threat model will be evaluated against the final transaction
  --   with the UTxO state captured before that transaction executed.
  --   Default: no threat models.
  threatModels :: [ThreatModel ()]
  threatModels = []

  -- | Threat models that are expected to find vulnerabilities.
  --   These are run like 'threatModels' but with inverted pass/fail semantics:
  --
  --   * OK when a vulnerability IS detected
  --   * FAIL when a vulnerability is NOT detected
  --
  --   Output is quiet — no verbose transaction dumps.
  --   Default: empty, backward compatible.
  expectedVulnerabilities :: [ThreatModel ()]
  expectedVulnerabilities = []

  -- | Whether to discard (skip) test cases where the invalid action fails due to
  --   a user-level error (e.g., off-chain balancing failure) rather than an
  --   on-chain validator rejection during negative testing.
  --
  --   When 'True', negative tests that throw user exceptions are discarded
  --   (via QuickCheck's 'discard'), so only on-chain rejections count as
  --   successful negative tests.
  --
  --   When 'False' (the default), user exceptions also cause the test case
  --   to be discarded — meaning both off-chain and on-chain failures are
  --   treated the same way.
  --
  --   Override this in your 'TestingInterface' instance if you need finer
  --   control over which failure modes are accepted in negative testing.
  discarNegativeTestForUserExceptions :: Bool
  discarNegativeTestForUserExceptions = False

{- | Tests run in the mockchain monad extended with balancing error handling.

Leaving handling of balancing errors to the testing interface is important because
the errors can contain data for code coverage.
-}
newtype TestingMonadT m a = TestingMonad
  { runTestingMonadT :: ExceptT (BalanceTxError C.ConwayEra) (MockchainT C.ConwayEra m) a
  }
  deriving newtype
    ( Functor
    , Applicative
    , Monad
    , C.MonadError (BalanceTxError C.ConwayEra)
    , C.MonadIO
    , MonadLog
    , MonadFail
    , MonadBlockchain C.ConwayEra
    , MonadMockchain C.ConwayEra
    )

-- | Opaque wrapper for model state
newtype ModelState state = ModelState {unModelState :: state}
  deriving (Eq, Show)

{- | Per-threat-model accumulated results across all QuickCheck iterations.
Key is the threat model name, value is the list of outcomes (one per iteration).
-}
type ThreatModelResults = Map.Map String [ThreatModelOutcome]

-- | A sequence of actions to perform
newtype Actions state = Actions_ [Action state]

newtype InvalidActions state = InvalidActions (Actions state, Action state)

instance (TestingInterface state, Show (Action state)) => Show (InvalidActions state) where
  show (InvalidActions (Actions prefix, bad)) =
    "InvalidActions " ++ show prefix ++ " then " ++ show bad

pattern Actions :: [Action state] -> Actions state
pattern Actions as = Actions_ as
{-# COMPLETE Actions #-}

instance (TestingInterface state, Show (Action state)) => Show (Actions state) where
  show (Actions acts) = "Actions " ++ show acts

instance (TestingInterface state) => Arbitrary (Actions state) where
  arbitrary = Actions <$> genActions initialState 10

instance (TestingInterface state) => Arbitrary (InvalidActions state) where
  arbitrary = do
    -- Generate a valid prefix (builds up state)
    prefix <- genActions initialState 10
    let finalState = foldl nextState initialState prefix
    -- Generate an action that VIOLATES the precondition in that state
    maybeInvalid <- arbitraryAction finalState `suchThatMaybe` (not . precondition finalState)
    case maybeInvalid of
      Nothing -> discard -- tell QuickCheck to skip this case
      Just bad -> pure $ InvalidActions (Actions_ prefix, bad)

-- | Try up to 100 times to generate a value satisfying a predicate
suchThatMaybe :: Gen a -> (a -> Bool) -> Gen (Maybe a)
suchThatMaybe gen p = go (100 :: Int)
 where
  go 0 = pure Nothing
  go retries = do
    a <- gen
    if p a then pure (Just a) else go (retries - 1)

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

-- | Options for running property tests
data RunOptions = RunOptions
  { verbose :: Bool
  -- ^ Print actions as they are executed
  , maxActions :: Int
  -- ^ Maximum number of actions to generate
  , mcOptions :: Options C.ConwayEra
  , disableNegativeTesting :: Maybe String
  -- ^ If @Just reason@, negative tests are skipped (shown as IGNORED) with the given reason.
  --   If @Nothing@, negative tests run normally. Default: @Nothing@.
  }

defaultRunOptions :: RunOptions
defaultRunOptions =
  RunOptions
    { verbose = False
    , maxActions = 10
    , mcOptions = defaultOptions
    , disableNegativeTesting = Nothing
    }

{- | Main property for testing a testing interface.
Generates random action sequences and checks that the implementation matches the model.
-}
propRunActions :: forall state. (TestingInterface state, Show (Action state)) => String -> TestTree
propRunActions name = propRunActionsWithOptions @state name defaultRunOptions

-- | Run testing interface tests with custom options
propRunActionsWithOptions
  :: forall state
   . (TestingInterface state, Show (Action state))
  => String
  -> RunOptions
  -> TestTree
propRunActionsWithOptions groupName opts =
  let tms = threatModels @state
      evs = expectedVulnerabilities @state
   in if null tms && null evs
        then
          -- No threat models: simple structure (backward compatible)
          testGroup
            groupName
            [ testProperty "Positive tests" (positiveTest @state opts Nothing [] [])
            , negativeTestTree
            ]
        else
          -- Has threat models: two-phase approach with IORef
          withResource (newIORef Map.empty) (\_ -> pure ()) $ \getTmResultsRef ->
            sequentialTestGroup groupName AllFinish $
              [ testProperty "Positive tests" (positiveTest @state opts (Just getTmResultsRef) tms evs)
              , negativeTestTree
              ]
                <> threatModelGroup getTmResultsRef tms
                <> expectedVulnGroup getTmResultsRef evs
 where
  negativeTestTree = case disableNegativeTesting opts of
    Nothing -> testProperty "Negative tests" (negativeTest @state opts)
    Just reason -> ignoreTestBecause reason $ testProperty "Negative tests" (negativeTest @state opts)

  threatModelGroup _ [] = []
  threatModelGroup getTmResultsRef tms' =
    [testGroup "Threat models" $ zipWith (threatModelTestCase getTmResultsRef) [1 ..] tms']

  expectedVulnGroup _ [] = []
  expectedVulnGroup getTmResultsRef evs' =
    [testGroup "Expected vulnerabilities" $ zipWith (expectedVulnTestCase getTmResultsRef) [1 ..] evs']

-- | Negative test: check that invalid actions fail
negativeTest
  :: forall state
   . (TestingInterface state, Show (Action state))
  => RunOptions
  -> InvalidActions state
  -> Property
negativeTest opts (InvalidActions (Actions actions, badAction)) = monadicIO $ do
  let RunOptions{mcOptions = Options{coverageRef, params}} = opts
      initialSt = initialState @state

  when (verbose opts) $
    monitor (counterexample $ "Initial state: " ++ show initialSt)

  -- Phase 1: Run the valid prefix, capturing the final mockchain state
  (prefixResult, prefixState) <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ runTestingMonadT $ do
    foldM (runAction opts) initialSt actions

  -- Phase 2: Run the bad action starting from the state left by the valid prefix
  case prefixResult of
    Left err -> do
      monitor (counterexample $ "Valid prefix failed: " ++ show err)
      pure (property False)
    Right finalState -> do
      let monadAction = runExceptT $ runTestingMonadT $ perform finalState badAction
      result' <- run $ try @SomeException $ runMockchainIO monadAction params prefixState
      -- We distinguish between validation errors and user errors:
      -- if the action failed at the off-chain level (e.g. balancing), we discard the test,
      -- but if it failed after submission (i.e. validator rejection), we count it as a success.
      case result' of
        -- we try another round of bad actions
        Left _ | discarNegativeTestForUserExceptions @state -> discard
        Left _ -> pure (property True)
        Right result ->
          case result of
            (Left err, MockChainState{mcsCoverageData = covData}) -> do
              -- Good: the invalid action failed via BalanceTxError (validator rejection)
              for_ coverageRef $ \ref -> liftIO $ modifyIORef ref (<> (covData <> coverageFromBalanceTxError err))
              pure (property True)
            (Right _, MockChainState{mcsCoverageData = covData}) -> do
              -- Bad: the invalid action succeeded — contract is too permissive
              for_ coverageRef $ \ref -> liftIO $ modifyIORef ref (<> covData)
              monitor (counterexample $ "Expected failure for invalid action but it succeeded")
              pure (property False)

{- | Positive test with optional threat model outcome collection.
When threat models list is empty, it behaves as a simple positive test.
When threat models are present, each is run in isolation with exception handling.
-}
positiveTest
  :: forall state
   . (TestingInterface state, Show (Action state))
  => RunOptions
  -> Maybe (IO (IORef ThreatModelResults))
  -- ^ IORef for collecting results (Nothing = no threat models, don't collect)
  -> [ThreatModel ()]
  -- ^ Threat models (early-stop on TMFailed)
  -> [ThreatModel ()]
  -- ^ Expected vulnerabilities (never early-stop)
  -> Actions state
  -> Property
positiveTest opts mGetTmResultsRef tms evs (Actions actions) = monadicIO $ do
  let RunOptions{mcOptions = Options{coverageRef, params}} = opts
      initialSt = initialState @state

  when (verbose opts) $
    monitor (counterexample $ "Initial state: " ++ show initialSt)

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ runTestingMonadT $ do
    (finalState, lastUtxoBefore, lastMockChainState) <-
      foldM
        ( \(state, _, _) action -> do
            utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
            mcStateBefore <- getMockChainState
            newState <- runAction opts state action
            pure (newState, Just utxoBefore, Just mcStateBefore)
        )
        (initialSt, Nothing, Nothing)
        actions
    -- Get the last transaction
    allTxs <- getTxs
    let lastTx = if null allTxs then Nothing else Just (head allTxs)

    -- Run threat models in isolation
    -- Note: runThreatModelCheck handles rebalancing failures internally (returns TMSkipped)
    -- so we don't need to catch exceptions here. Any remaining exception is a genuine bug.
    -- Once a threat model has failed (TMFailed), we skip running it on subsequent transactions.
    tmResultsWithCov <- case (lastTx, lastUtxoBefore, lastMockChainState) of
      (Just tx, Just utxo, Just mcState) -> do
        let pparams' = params ^. ledgerProtocolParameters
            env = ThreatModelEnv tx utxo pparams'
        -- Check which threat models have already failed (from previous QuickCheck iterations)
        existingResults <- case mGetTmResultsRef of
          Just getTmRef -> liftIO $ do
            tmRef <- getTmRef
            readIORef tmRef
          Nothing -> pure Map.empty
        let isTMFailed (TMFailed _) = True
            isTMFailed _ = False
            alreadyFailed name = any isTMFailed (fromMaybe [] (Map.lookup name existingResults))
            -- Only filter threat models (tms) for early-stop; expected vulnerabilities (evs) always run
            tmsToRun = filter (not . alreadyFailed . fromMaybe "Unnamed" . getThreatModelName) tms
            allToRun = tmsToRun <> evs -- evs always run, no filtering
            -- Run each threat model in an isolated MockchainT context
        liftIO $ forM allToRun $ \tm -> do
          let name = fromMaybe "Unnamed" (getThreatModelName tm)
          (outcome, tmFinalState) <-
            runMockchainIO (runThreatModelCheck Wallet.w1 tm [env]) params mcState
          pure (name, outcome, mcsCoverageData tmFinalState)
      _ -> pure []

    -- Extract just the (name, outcome) pairs for downstream processing
    let tmResults = [(n, o) | (n, o, _) <- tmResultsWithCov]
        -- Aggregate coverage from all threat model runs
        tmCoverage = mconcat [cov | (_, _, cov) <- tmResultsWithCov]

    pure (finalState, tmResults, tmCoverage)

  case result of
    (Left err, MockChainState{mcsCoverageData = covData}) -> do
      -- Extract and accumulate coverage from the failure
      for_ coverageRef $ \ref -> liftIO $ modifyIORef ref (<> (covData <> coverageFromBalanceTxError err))
      pure (property False)
    (Right (finalState, tmResults, tmCoverage), MockChainState{mcsCoverageData = covData}) -> do
      monitor (counterexample $ "Final state: " ++ show finalState)
      -- accumulate coverage from positive test AND threat model runs
      traverse_ (\ref -> liftIO $ modifyIORef ref (<> covData <> tmCoverage)) coverageRef
      -- Store threat model results in the shared IORef (if present)
      case mGetTmResultsRef of
        Just getTmResultsRef -> run $ do
          tmRef <- getTmResultsRef
          modifyIORef tmRef $ \existing ->
            foldl'
              (\m (name, outcome) -> Map.insertWith (<>) name [outcome] m)
              existing
              tmResults
        Nothing -> pure ()
      pure (property True) -- Positive test passes independently of threat models

-- | Create a test case for displaying threat model results
threatModelTestCase
  :: IO (IORef ThreatModelResults)
  -> Int
  -- ^ Index for fallback naming
  -> ThreatModel ()
  -- ^ The threat model
  -> TestTree
threatModelTestCase getTmResultsRef idx tm =
  let name = fromMaybe ("Threat model " <> show idx) (getThreatModelName tm)
   in testCaseSteps name $ \step -> do
        tmRef <- getTmResultsRef
        allResults <- readIORef tmRef
        let outcomes = fromMaybe [] (Map.lookup name allResults)
            total = length outcomes
            numPassed = length [() | TMPassed <- outcomes]
            numSkipped = length [() | TMSkipped <- outcomes]
            numErrors = length [() | TMError _ <- outcomes]
            errors = [msg | TMError msg <- outcomes]

        -- Report errors as warnings (don't fail the test)
        case errors of
          [] -> pure ()
          _ -> do
            step $ "WARNING: " <> show numErrors <> " error(s) during threat model execution"
            mapM_ (step . ("  " <>)) (take 3 errors)
            case drop 3 errors of
              [] -> pure ()
              remaining -> step $ "  ... and " <> show (length remaining) <> " more"

        if total == 0
          then step "No transactions were generated by positive tests"
          else
            if numSkipped + numErrors == total
              then
                step $
                  "SKIPPED: Precondition never met (0/"
                    <> show total
                    <> " transactions applicable)"
              else do
                step $
                  "Tested "
                    <> show numPassed
                    <> "/"
                    <> show total
                    <> " transactions ("
                    <> show numSkipped
                    <> " skipped, "
                    <> show numErrors
                    <> " errors)"
                case [msg | TMFailed msg <- outcomes] of
                  [] -> pure ()
                  (firstFailure : rest) ->
                    assertFailure $
                      unlines
                        [ "FAILED (after " <> show (numPassed + 1) <> " tests): Vulnerability detected"
                        , ""
                        , firstFailure
                        , if null rest
                            then ""
                            else "... and " <> show (length rest) <> " more similar failure(s) suppressed"
                        ]

{- | Create a test case for expected vulnerabilities with inverted pass/fail semantics.
TMFailed = GOOD (vulnerability was correctly detected)
TMPassed = BAD (vulnerability was NOT found when expected)
TMError = WARNING (threat model crashed, doesn't count as found or not found)
Output is quiet — no verbose transaction dump details, just stats.
-}
expectedVulnTestCase
  :: IO (IORef ThreatModelResults)
  -> Int
  -- ^ Index for fallback naming
  -> ThreatModel ()
  -- ^ The threat model expected to find vulnerabilities
  -> TestTree
expectedVulnTestCase getTmResultsRef idx tm =
  let name = fromMaybe ("Expected vulnerability " <> show idx) (getThreatModelName tm)
   in testCaseSteps name $ \step -> do
        tmRef <- getTmResultsRef
        allResults <- readIORef tmRef
        let outcomes = fromMaybe [] (Map.lookup name allResults)
            total = length outcomes
            -- In expected vulnerability context:
            -- TMFailed = vulnerability detected = GOOD
            -- TMPassed = no vulnerability found = BAD
            -- TMError = crashed, doesn't count either way
            numFound = length [() | TMFailed _ <- outcomes] -- Good: vulnerability detected
            numNotFound = length [() | TMPassed <- outcomes] -- Bad: expected vuln not found
            numSkipped = length [() | TMSkipped <- outcomes]
            numErrors = length [() | TMError _ <- outcomes]
            errors = [msg | TMError msg <- outcomes]
            tested = numFound + numNotFound

        -- Report errors as warnings (don't fail the test for errors alone)
        case errors of
          [] -> pure ()
          _ -> do
            step $ "WARNING: " <> show numErrors <> " error(s) during threat model execution"
            mapM_ (step . ("  " <>)) (take 3 errors)
            case drop 3 errors of
              [] -> pure ()
              remaining -> step $ "  ... and " <> show (length remaining) <> " more"

        if total == 0
          then step "No transactions were generated by positive tests"
          else
            if numSkipped + numErrors == total
              then
                step $
                  "SKIPPED: Precondition never met (0/"
                    <> show total
                    <> " transactions applicable)"
              else
                if numFound > 0
                  then
                    -- Good: at least one vulnerability was found
                    step $
                      "Vulnerability detected ("
                        <> show numFound
                        <> "/"
                        <> show tested
                        <> " transactions, "
                        <> show numSkipped
                        <> " skipped, "
                        <> show numErrors
                        <> " errors)"
                  else
                    if tested > 0
                      then
                        -- Bad: transactions were tested but no vulnerability found
                        assertFailure $
                          "Expected vulnerability NOT found in "
                            <> show tested
                            <> " tested transactions"
                      else
                        -- Edge case: all were skipped/errored (same as numSkipped + numErrors == total, but defensive)
                        step $
                          "SKIPPED: Precondition never met (0/"
                            <> show total
                            <> " transactions applicable)"

-- | Execute a single action and update the model state
runAction
  :: (TestingInterface state, Show (Action state))
  => RunOptions
  -> state
  -> Action state
  -> TestingMonadT IO state
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

{- | Configuration for coverage collection and reporting.

Use with 'withCoverage' to set up coverage tracking for your test suite.
-}
data CoverageConfig = CoverageConfig
  { coverageIndices :: [CoverageIndex]
  -- ^ Coverage indices from compiled scripts (obtained via @'PlutusTx.Code.getCovIdx'@).
  --   Multiple indices are combined with @'<>'@.
  , coverageReport :: CoverageReport -> IO ()
  -- ^ Action to perform with the final coverage report.
  --   Use 'printCoverageReport', 'writeCoverageReport', or 'silentCoverageReport'.
  }

-- | Print a coverage report to stdout using prettyprinter.
printCoverageReport :: CoverageReport -> IO ()
printCoverageReport = print . Pretty.pretty

-- | Write a coverage report to a file.
writeCoverageReport :: FilePath -> CoverageReport -> IO ()
writeCoverageReport fp cr = do
  writeFile fp (show (Pretty.pretty cr))
  printCoveragePath fp

printCoveragePath :: FilePath -> IO ()
printCoveragePath fp = putStrLn $ "Coverage report available at: " <> fp

-- | Collect coverage data but discard the report.
silentCoverageReport :: CoverageReport -> IO ()
silentCoverageReport _ = pure ()

-- | Compact representation of a source location for JSON output.
data JsonCovLoc = JsonCovLoc
  { jclFile :: String
  , jclStartLine :: Int
  , jclStartCol :: Int
  , jclEndLine :: Int
  , jclEndCol :: Int
  }
  deriving (Generic)

instance ToJSON JsonCovLoc where
  toJSON (JsonCovLoc f sl sc el ec) =
    Aeson.object
      [ Key.fromString "file" .= f
      , Key.fromString "startLine" .= sl
      , Key.fromString "startCol" .= sc
      , Key.fromString "endLine" .= el
      , Key.fromString "endCol" .= ec
      ]

-- | Compact representation of a coverage annotation for JSON output.
data JsonAnnotation
  = JsonLocation JsonCovLoc
  | JsonBool JsonCovLoc Bool

instance ToJSON JsonAnnotation where
  toJSON (JsonLocation loc) =
    Aeson.object
      [ Key.fromString "type" .= ("location" :: String)
      , Key.fromString "loc" .= loc
      ]
  toJSON (JsonBool loc b) =
    Aeson.object
      [ Key.fromString "type" .= ("bool" :: String)
      , Key.fromString "loc" .= loc
      , Key.fromString "value" .= b
      ]

-- | A covered annotation with optional function name metadata.
data JsonCovered = JsonCovered
  { jcAnnotation :: JsonAnnotation
  , jcSymbols :: [String]
  }
  deriving (Generic)

instance ToJSON JsonCovered where
  toJSON (JsonCovered ann syms) =
    Aeson.object
      [ Key.fromString "annotation" .= ann
      , Key.fromString "symbols" .= syms
      ]

-- | Minimal coverage summary matching what Pretty.pretty shows.
data CoverageSummary = CoverageSummary
  { csCovered :: [JsonCovered]
  , csUncovered :: [JsonAnnotation]
  , csIgnored :: [JsonAnnotation]
  }
  deriving (Generic)

instance ToJSON CoverageSummary where
  toJSON (CoverageSummary cov uncov ign) =
    Aeson.object
      [ Key.fromString "covered" .= cov
      , Key.fromString "uncovered" .= uncov
      , Key.fromString "ignored" .= ign
      ]

-- | Convert a CovLoc to compact JSON representation.
toJsonCovLoc :: CovLoc -> JsonCovLoc
toJsonCovLoc (CovLoc f sl el sc ec) = JsonCovLoc f sl sc el ec

-- | Convert a CoverageAnnotation to compact JSON representation.
toJsonAnnotation :: CoverageAnnotation -> JsonAnnotation
toJsonAnnotation (CoverLocation loc) = JsonLocation (toJsonCovLoc loc)
toJsonAnnotation (CoverBool loc b) = JsonBool (toJsonCovLoc loc) b

-- | Extract symbol names from Metadata.
extractSymbols :: Set.Set Metadata -> [String]
extractSymbols = foldr go []
 where
  go (ApplicationHeadSymbol s) acc = s : acc
  go IgnoredAnnotation acc = acc

-- | Convert a CoverageReport to a compact summary (same info as Pretty.pretty shows).
coverageSummary :: CoverageReport -> CoverageSummary
coverageSummary (CoverageReport idx covData) =
  CoverageSummary
    { csCovered =
        [ JsonCovered (toJsonAnnotation ann) (extractSymbols $ metadataFor ann)
        | ann <- Set.toList $ allAnns `Set.intersection` coveredAnns'
        ]
    , csUncovered = map toJsonAnnotation . Set.toList $ uncoveredAnns
    , csIgnored = map toJsonAnnotation . Set.toList $ ignoredAnns' Set.\\ coveredAnns'
    }
 where
  allAnns = idx ^. coverageAnnotations
  coveredAnns' = covData ^. coveredAnnotations
  ignoredAnns' = idx ^. ignoredAnnotations
  uncoveredAnns = allAnns Set.\\ (coveredAnns' <> ignoredAnns')
  metadataFor ann = maybe Set.empty _metadataSet $ Map.lookup ann (idx ^. coverageMetadata)

-- | Print a coverage report as compact JSON to stdout.
printCoverageJSON :: CoverageReport -> IO ()
printCoverageJSON = LBS.putStrLn . Aeson.encode . coverageSummary

-- | Write a coverage report as compact JSON to a file.
writeCoverageJSON :: FilePath -> CoverageReport -> IO ()
writeCoverageJSON fp report = do
  LBS.writeFile fp $ Aeson.encode $ coverageSummary report
  printCoveragePath fp

-- | Print a coverage report as pretty-printed JSON to stdout.
printCoverageJSONPretty :: CoverageReport -> IO ()
printCoverageJSONPretty = LBS.putStrLn . Aeson.encodePretty . coverageSummary

-- | Write a coverage report as pretty-printed JSON to a file.
writeCoverageJSONPretty :: FilePath -> CoverageReport -> IO ()
writeCoverageJSONPretty fp report = do
  LBS.writeFile fp $ Aeson.encodePretty $ coverageSummary report
  printCoveragePath fp

{- | Run a test suite with Plutus script coverage collection.

Creates the coverage 'IORef', wires it into 'Options' and 'RunOptions',
runs the user's action, and on exit produces a 'CoverageReport' from the
accumulated data.

The report is generated when the inner action throws an 'ExitCode' exception
(which is how @tasty@'s 'Test.Tasty.defaultMain' signals completion). The
original exception is re-thrown after the report action runs.

@
main :: IO ()
main = withCoverage config $ \\opts runOpts ->
  defaultMain $ testGroup \"my tests\"
    [ testCase \"t1\" (mockchainSucceedsWithOptions opts myTest)
    , myPropertyTests runOpts
    ]
 where
  config = CoverageConfig
    { coverageIndices = [myScriptCovIdx]
    , coverageReport  = printCoverageReport
    }
@
-}
withCoverage
  :: CoverageConfig
  -> (Options C.ConwayEra -> RunOptions -> IO ())
  -> IO ()
withCoverage CoverageConfig{coverageIndices, coverageReport = reportAction} k = do
  ref <- newIORef mempty
  let opts = defaultOptions{coverageRef = Just ref}
      runOpts = defaultRunOptions{mcOptions = opts}
  k opts runOpts
    `catch` \(e :: ExitCode) -> do
      covData <- readIORef ref
      let combinedIdx = mconcat coverageIndices
          report = CoverageReport combinedIdx covData
      reportAction report
      throwIO e

-- | Options for running the testing monad.
data Options era = Options
  { params :: NodeParams era
  , coverageRef :: Maybe (IORef CoverageData)
  }

defaultOptions :: Options C.ConwayEra
defaultOptions =
  Options
    { params = Defaults.nodeParams
    , coverageRef = Nothing
    }

-- | Modify the maximum transaction size in the protocol parameters of the given options
modifyTransactionLimits :: Options C.ConwayEra -> Word32 -> Options C.ConwayEra
modifyTransactionLimits opts@Options{params = Defaults.pParams -> pp} newVal =
  -- TODO: use lenses to make this cleaner
  opts
    { params = (params opts){npProtocolParameters = C.LedgerProtocolParameters $ pp & L.ppMaxTxSizeL .~ newVal}
    }

-- | Run the 'TestingMonadT' action with the given options and fail if there is an error
mockchainSucceedsWithOptions :: Options C.ConwayEra -> TestingMonadT IO a -> Assertion
mockchainSucceedsWithOptions Options{params, coverageRef} action =
  runMockchain0IOWith Wallet.initialUTxOs params (runExceptT (runTestingMonadT action))
    >>= \(res, st) -> do
      let covData = st ^. coverageData
      for_ coverageRef $ \ref -> modifyIORef ref (<> covData)
      case res of
        Right _ -> pure ()
        Left err -> do
          for_ coverageRef $ \ref -> modifyIORef ref (<> coverageFromBalanceTxError err)
          fail $ show err

{- | Run the 'TestingMonadT' action with the given options, fail if it
    succeeds, and handle the error appropriately.
-}
mockchainFailsWithOptions :: Options C.ConwayEra -> TestingMonadT IO a -> (BalanceTxError C.ConwayEra -> Assertion) -> Assertion
mockchainFailsWithOptions Options{params, coverageRef} action handleError =
  runMockchain0IOWith Wallet.initialUTxOs params (runExceptT (runTestingMonadT action))
    >>= \(res, st) -> do
      let covData = st ^. coverageData
      for_ coverageRef $ \ref -> modifyIORef ref (<> covData)
      case res of
        Right _ -> fail "mockchainFailsWithOptions: Did not fail"
        Left err -> do
          for_ coverageRef $ \ref -> modifyIORef ref (<> coverageFromBalanceTxError err)
          handleError err
