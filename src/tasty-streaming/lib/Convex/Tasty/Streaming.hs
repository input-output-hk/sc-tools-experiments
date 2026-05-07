module Convex.Tasty.Streaming (
  streamingJsonReporter,
  listTestsJsonIngredient,
  streamingIngredients,
  defaultMainStreaming,
) where

import Control.Concurrent.Async (forConcurrently_)
import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Concurrent.STM
import Control.Monad (when)
import Convex.Tasty.Streaming.TMSummary (
  TMRecorder,
  TMStoreOption (..),
  TraceRecorder (..),
  lookupThreatModelSummary,
  newTMStore,
  storeRecorder,
 )
import Convex.Tasty.Streaming.TreeMap (buildTestMap)
import Convex.Tasty.Streaming.Types
import Data.Aeson (encode)
import Data.ByteString.Lazy.Char8 qualified as BL8
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.IntMap.Strict (IntMap)
import Data.IntMap.Strict qualified as IntMap
import Data.Proxy (Proxy (..))
import Data.Tagged (Tagged (..))
import Data.Text qualified as Text
import Data.Typeable (Typeable)
import System.IO (BufferMode (..), hFlush, hSetBuffering, stdout)
import Test.Tasty (TestTree, defaultMainWithIngredients, localOption)
import Test.Tasty.Ingredients (Ingredient (..))
import Test.Tasty.Ingredients.ConsoleReporter (consoleTestReporter)
import Test.Tasty.Options (IsOption (..), OptionDescription (..), lookupOption, mkFlagCLParser, safeRead)
import Test.Tasty.Runners (
  FailureReason (..),
  Outcome (..),
  Progress (..),
  Result (..),
  Status (..),
  listingTests,
 )

-- | Command-line option to enable streaming JSON output
newtype StreamingJson = StreamingJson Bool
  deriving (Eq, Ord, Typeable)

instance IsOption StreamingJson where
  defaultValue = StreamingJson False
  parseValue = fmap StreamingJson . safeRead
  optionName = Tagged "streaming-json"
  optionHelp = Tagged "Enable streaming NDJSON test output to stdout"
  optionCLParser = mkFlagCLParser mempty (StreamingJson True)

-- | Command-line option to disable iteration trace collection
newtype NoTrace = NoTrace Bool
  deriving (Eq, Ord, Typeable)

instance IsOption NoTrace where
  defaultValue = NoTrace False
  parseValue = fmap NoTrace . safeRead
  optionName = Tagged "no-trace"
  optionHelp = Tagged "Disable iteration trace collection (only effective with --streaming-json)"
  optionCLParser = mkFlagCLParser mempty (NoTrace True)

-- | Command-line option to list tests as JSON without running them
newtype ListTestsJson = ListTestsJson Bool
  deriving (Eq, Ord, Typeable)

instance IsOption ListTestsJson where
  defaultValue = ListTestsJson False
  parseValue = fmap ListTestsJson . safeRead
  optionName = Tagged "list-tests-json"
  optionHelp = Tagged "List all tests as a JSON object and exit without running"
  optionCLParser = mkFlagCLParser mempty (ListTestsJson True)

{- | Internal option carrying a shared 'IORef Bool' that is set to 'True' by
the streaming reporter when @--streaming-json@ is active.  The
'TraceRecorder' callback checks this before emitting any events.
-}
newtype StreamingEnabledRef = StreamingEnabledRef (Maybe (IORef Bool))

instance IsOption StreamingEnabledRef where
  defaultValue = StreamingEnabledRef Nothing
  parseValue = const Nothing
  optionName = Tagged "streaming-enabled-ref"
  optionHelp = Tagged "internal: streaming enabled flag"

{- | Internal option carrying a shared 'MVar ()' so the reporter and the
'TraceRecorder' use the same output lock, preventing interleaved NDJSON lines.
-}
newtype OutputLockRef = OutputLockRef (Maybe (MVar ()))

instance IsOption OutputLockRef where
  defaultValue = OutputLockRef Nothing
  parseValue = const Nothing
  optionName = Tagged "output-lock-ref"
  optionHelp = Tagged "internal: shared output lock"

{- | Internal option carrying a shared 'IORef' so the reporter can publish the
test map and the 'TraceRecorder' can read it back to resolve test IDs.
-}
newtype TestMapRef = TestMapRef (Maybe (IORef (IntMap TestInfo)))

instance IsOption TestMapRef where
  defaultValue = TestMapRef Nothing
  parseValue = const Nothing
  optionName = Tagged "test-map-ref"
  optionHelp = Tagged "internal: shared test map reference"

{- | The streaming JSON reporter ingredient.

When activated via @--streaming-json@, replaces console output with
newline-delimited JSON events streamed to stdout.
-}
streamingJsonReporter :: Ingredient
streamingJsonReporter = TestReporter
  [ Option (Proxy :: Proxy StreamingJson)
  , Option (Proxy :: Proxy NoTrace)
  , Option (Proxy :: Proxy TMStoreOption)
  , Option (Proxy :: Proxy TMRecorder)
  , Option (Proxy :: Proxy TraceRecorder)
  , Option (Proxy :: Proxy TestMapRef)
  , Option (Proxy :: Proxy StreamingEnabledRef)
  , Option (Proxy :: Proxy OutputLockRef)
  ]
  $ \opts tree -> do
    let StreamingJson enabled = lookupOption opts
    if not enabled
      then Nothing
      else Just $ \statusMap -> do
        let TMStoreOption mStore = lookupOption opts
            TestMapRef mTestMapRef = lookupOption opts
            StreamingEnabledRef mEnabledRef = lookupOption opts

        -- Signal that streaming is active so the TraceRecorder callback
        -- (which checks the same IORef) actually emits events.
        -- When --no-trace is passed, leave the ref as False so that both
        -- trEnabled and recordIteration remain no-ops.
        let NoTrace noTrace = lookupOption opts
        case mEnabledRef of
          Just ref -> writeIORef ref (not noTrace)
          Nothing -> pure ()

        -- Set line buffering for streaming
        hSetBuffering stdout LineBuffering

        -- Use the shared output lock if provided, otherwise create a new one
        -- (backward compatibility when the reporter is used without
        -- defaultMainStreaming).
        let OutputLockRef mSharedLock = lookupOption opts
        outputLock <- maybe (newMVar ()) pure mSharedLock
        let emit evt = withMVar outputLock $ \_ -> emitEvent evt

        -- Build the test index -> metadata map
        testMap <- buildTestMap opts tree

        -- Populate the shared test map ref so TraceRecorder can resolve IDs
        case mTestMapRef of
          Just ref -> writeIORef ref testMap
          Nothing -> pure ()

        -- Emit suite_started with full test list
        let testInfos = map snd $ IntMap.toAscList testMap
        emit $ SuiteStarted testInfos

        -- Track results for final summary
        resultsVar <- newTVarIO ([] :: [(Int, Result)])

        -- Watch each test concurrently
        forConcurrently_ (IntMap.toAscList statusMap) $ \(idx, statusTVar) -> do
          -- Wait until the test starts
          atomically $ do
            status <- readTVar statusTVar
            case status of
              NotStarted -> retry
              _ -> pure ()

          -- Emit test_started
          emit $ TestStarted idx

          -- Wait for completion, emitting progress events along the way
          let waitLoop lastSeen = do
                next <- atomically $ do
                  status <- readTVar statusTVar
                  case status of
                    NotStarted -> retry
                    Executing p ->
                      let cur = (progressText p, progressPercent p)
                       in if Just cur == lastSeen
                            then retry
                            else pure (Left p)
                    Done r -> pure (Right r)
                case next of
                  Left p -> do
                    emit $
                      TestProgress
                        { epId = idx
                        , epMessage = Text.pack (progressText p)
                        , epPercent = progressPercent p
                        }
                    waitLoop (Just (progressText p, progressPercent p))
                  Right r -> pure r
          result <- waitLoop Nothing

          -- Record result
          atomically $ modifyTVar' resultsVar ((idx, result) :)

          -- Look up structured threat-model summary by "<group>/<name>" key
          let testInfo = IntMap.lookup idx testMap
              key = case testInfo of
                Just ti
                  | (parent : _) <- reverse (tiPath ti) ->
                      Text.unpack parent <> "/" <> Text.unpack (tiName ti)
                Just ti -> Text.unpack (tiName ti)
                Nothing -> ""
          mSummary <- case mStore of
            Just store -> lookupThreatModelSummary store key
            Nothing -> pure Nothing

          -- Emit test_done
          let outcome = case resultOutcome result of
                Success -> TestSuccess
                Failure reason ->
                  TestFailure $
                    FailureInfo
                      { fiReason = Text.pack $ showFailureReason reason
                      , fiMessage = Text.pack (resultDescription result)
                      }
          emit $
            TestDone
              { edId = idx
              , edOutcome = outcome
              , edDuration = resultTime result
              , edDescription = Text.pack (resultDescription result)
              , edThreatModel = mSummary
              }

        -- Emit suite_done summary
        allResults <- readTVarIO resultsVar
        let passed = length [() | (_, r) <- allResults, isSuccess r]
        let failed = length allResults - passed

        -- Return the "finalize" callback
        pure $ \totalTime -> do
          emit $ SuiteDone passed failed totalTime
          pure (failed == 0)

-- | Emit a single NDJSON event line to stdout
emitEvent :: Event -> IO ()
emitEvent evt = do
  BL8.putStrLn (encode evt)
  hFlush stdout

-- | Check if a Result is a success
isSuccess :: Result -> Bool
isSuccess r = case resultOutcome r of
  Success -> True
  _ -> False

-- | Show a FailureReason as text
showFailureReason :: FailureReason -> String
showFailureReason TestFailed = "TestFailed"
showFailureReason (TestThrewException e) = "TestThrewException: " ++ show e
showFailureReason (TestTimedOut n) = "TestTimedOut: " ++ show n ++ "μs"
showFailureReason TestDepFailed = "TestDepFailed"

{- | Find the Tasty test ID for a test identified by group name and category.
Searches the test map for a 'TestInfo' whose path contains the group name
and whose name matches the category (e.g. \"Positive tests\", \"Negative tests\").
Returns @-1@ as a fallback when the test is not found.
-}
findTestId :: IntMap TestInfo -> String -> String -> Int
findTestId testMap group category =
  let categoryName = case category of
        "positive" -> "Positive tests"
        "negative" -> "Negative tests"
        other -> other
      matches =
        IntMap.toList $
          IntMap.filter
            ( \ti ->
                Text.pack group `elem` tiPath ti
                  && tiName ti == Text.pack categoryName
            )
            testMap
   in case matches of
        ((testId, _) : _) -> testId
        [] -> -1 -- fallback: test not found

{- | Ingredient that lists the test tree as JSON and exits without running tests.

Activated via @--list-tests-json@.
-}
listTestsJsonIngredient :: Ingredient
listTestsJsonIngredient = TestManager
  [Option (Proxy :: Proxy ListTestsJson)]
  $ \opts tree -> do
    let ListTestsJson enabled = lookupOption opts
    if not enabled
      then Nothing
      else Just $ do
        hSetBuffering stdout LineBuffering
        testMap <- buildTestMap opts tree
        let testInfos = map snd $ IntMap.toAscList testMap
        emitEvent $ SuiteStarted testInfos
        pure True

-- | Default ingredients with streaming reporter added
streamingIngredients :: [Ingredient]
streamingIngredients = [listingTests, listTestsJsonIngredient, streamingJsonReporter, consoleTestReporter]

{- | Drop-in replacement for 'defaultMain' that supports @--streaming-json@.

If you bypass this entry point and wire 'streamingIngredients' manually,
threat-model summaries will not appear in the JSON output unless you
also call
@'localOption' ('TMStoreOption' (Just store)) . 'localOption' ('storeRecorder' store)@
on your tree (with a freshly-allocated store from 'newTMStore').
-}
defaultMainStreaming :: TestTree -> IO ()
defaultMainStreaming tree = do
  store <- newTMStore
  testMapRef <- newIORef IntMap.empty
  enabledRef <- newIORef False -- set to True by the reporter when --streaming-json is active
  -- Create a single shared output lock used by both the streaming reporter
  -- and the TraceRecorder so their NDJSON lines never interleave.
  outputLock <- newMVar ()
  -- Create a trace recorder that emits TestTrace events as NDJSON to stdout.
  -- The recorder reads the shared testMapRef (populated by the reporter at
  -- startup) to resolve the numeric Tasty test ID for each trace event.
  --
  -- Both 'trEnabled' and 'recordIteration' read the shared 'enabledRef',
  -- so when --streaming-json is NOT passed (or --no-trace is passed) the
  -- ref stays False: test bodies take the fast path and no NDJSON lines
  -- go to stdout.
  let traceRec =
        TraceRecorder
          { trEnabled = readIORef enabledRef
          , recordIteration = \group category iterationJson -> do
              enabled <- readIORef enabledRef
              when enabled $ do
                testMap <- readIORef testMapRef
                let testId = findTestId testMap group category
                withMVar outputLock $ \_ ->
                  emitEvent $
                    TestTrace
                      { ettTestId = testId
                      , ettCategory = Text.pack category
                      , ettTrace = iterationJson
                      }
          }
  let tree' =
        localOption (TMStoreOption (Just store)) $
          localOption (storeRecorder store) $
            localOption (TestMapRef (Just testMapRef)) $
              localOption (StreamingEnabledRef (Just enabledRef)) $
                localOption (OutputLockRef (Just outputLock)) $
                  localOption traceRec tree
  defaultMainWithIngredients streamingIngredients tree'
