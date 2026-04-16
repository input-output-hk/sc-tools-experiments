module Convex.Tasty.Streaming (
  streamingJsonReporter,
  listTestsJsonIngredient,
  streamingIngredients,
  defaultMainStreaming,
) where

import Control.Concurrent.Async (forConcurrently_)
import Control.Concurrent.MVar (newMVar, withMVar)
import Control.Concurrent.STM
import Convex.Tasty.Streaming.TreeMap (buildTestMap)
import Convex.Tasty.Streaming.Types
import Data.Aeson (encode)
import Data.ByteString.Lazy.Char8 qualified as BL8
import Data.IntMap.Strict qualified as IntMap
import Data.Proxy (Proxy (..))
import Data.Tagged (Tagged (..))
import Data.Text qualified as Text
import Data.Typeable (Typeable)
import System.IO (BufferMode (..), hFlush, hSetBuffering, stdout)
import Test.Tasty (TestTree, defaultMainWithIngredients)
import Test.Tasty.Ingredients (Ingredient (..))
import Test.Tasty.Ingredients.ConsoleReporter (consoleTestReporter)
import Test.Tasty.Options (IsOption (..), OptionDescription (..), lookupOption, mkFlagCLParser, safeRead)
import Test.Tasty.Runners (
  FailureReason (..),
  Outcome (..),
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

-- | Command-line option to list tests as JSON without running them
newtype ListTestsJson = ListTestsJson Bool
  deriving (Eq, Ord, Typeable)

instance IsOption ListTestsJson where
  defaultValue = ListTestsJson False
  parseValue = fmap ListTestsJson . safeRead
  optionName = Tagged "list-tests-json"
  optionHelp = Tagged "List all tests as a JSON object and exit without running"
  optionCLParser = mkFlagCLParser mempty (ListTestsJson True)

{- | The streaming JSON reporter ingredient.

When activated via @--streaming-json@, replaces console output with
newline-delimited JSON events streamed to stdout.
-}
streamingJsonReporter :: Ingredient
streamingJsonReporter = TestReporter
  [Option (Proxy :: Proxy StreamingJson)]
  $ \opts tree -> do
    let StreamingJson enabled = lookupOption opts
    if not enabled
      then Nothing
      else Just $ \statusMap -> do
        -- Set line buffering for streaming
        hSetBuffering stdout LineBuffering

        -- Create lock for thread-safe output
        outputLock <- newMVar ()
        let emit evt = withMVar outputLock $ \_ -> emitEvent evt

        -- Build the test index -> metadata map
        testMap <- buildTestMap opts tree

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

          -- Wait for completion
          result <- atomically $ do
            status <- readTVar statusTVar
            case status of
              Done r -> pure r
              _ -> retry

          -- Record result
          atomically $ modifyTVar' resultsVar ((idx, result) :)

          -- Emit test_done
          let testName = maybe "" tiName (IntMap.lookup idx testMap)
          let outcome = case resultOutcome result of
                Success -> TestSuccess
                Failure reason ->
                  TestFailure $
                    FailureInfo
                      { fiReason = Text.pack $ showFailureReason reason
                      , fiMessage = Text.pack $ resultDescription result
                      }
          emit $ TestDone idx outcome (resultTime result) testName

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

-- | Drop-in replacement for 'defaultMain' that supports @--streaming-json@.
defaultMainStreaming :: TestTree -> IO ()
defaultMainStreaming = defaultMainWithIngredients streamingIngredients
