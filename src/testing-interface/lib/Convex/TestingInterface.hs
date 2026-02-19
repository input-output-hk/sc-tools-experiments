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

import Control.Monad (foldM)
import Control.Monad.IO.Class (liftIO)
import Test.QuickCheck (Arbitrary (..), Gen, Property, conjoin, counterexample, elements, frequency, oneof, property)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)

import Cardano.Api qualified as C
import Convex.Class (getTxs, getUtxo)
import Convex.MockChain (MockChainState (MockChainState, mcsCoverageData), MockchainT, fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.Utils (Options (Options, coverageRef, params), defaultOptions)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Foldable (traverse_)
import Data.IORef (modifyIORef, newIORef, readIORef)

import Control.Lens ((^.))
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.ThreatModel (ThreatModel, ThreatModelEnv (..), runThreatModelM)

import Control.Exception (catch, throwIO)
import Data.Aeson (ToJSON (..), (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Encode.Pretty qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.ByteString.Lazy.Char8 qualified as LBS
import Data.Map qualified as Map
import Data.Set qualified as Set
import GHC.Generics (Generic)
import PlutusTx.Coverage (
  CovLoc (..),
  CoverageAnnotation (..),
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
  testGroup
    groupName
    [ testProperty "Positive tests" positiveTest
    ]
 where
  positiveTest :: Actions state -> Property
  positiveTest (Actions actions) = monadicIO $ do
    let RunOptions{mcOptions = Options{coverageRef, params}} = opts
        initialSt = initialState @state

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

      -- Run threat models INSIDE MockchainT with full Phase 1 + Phase 2 validation
      threatModelResult <- case (lastTx, lastUtxoBefore) of
        (Just tx, Just utxo) -> do
          let pparams' = params ^. ledgerProtocolParameters
              env = ThreatModelEnv tx utxo pparams'
          -- Use runThreatModelM with Wallet.w1 for re-balancing and re-signing
          -- TODO: now signs with w1; in future we may want to vary this
          conjoin <$> mapM (\tm -> runThreatModelM Wallet.w1 tm [env]) (threatModels @state)
        _ -> pure (property True)

      pure (finalState, threatModelResult)

    case result of
      ((finalState, threatModelProp), MockChainState{mcsCoverageData = covData}) -> do
        monitor (counterexample $ "Final state: " ++ show finalState)
        -- accumulate coverage
        traverse_ (\ref -> liftIO $ modifyIORef ref (<> covData)) coverageRef
        pure threatModelProp

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

{- | Configuration for coverage collection and reporting.

Use with 'withCoverage' to set up coverage tracking for your test suite.
-}
data CoverageConfig = CoverageConfig
  { coverageIndices :: [CoverageIndex]
  {- ^ Coverage indices from compiled scripts (obtained via @'PlutusTx.Code.getCovIdx'@).
  Multiple indices are combined with @'<>'@.
  -}
  , coverageReport :: CoverageReport -> IO ()
  {- ^ Action to perform with the final coverage report.
  Use 'printCoverageReport', 'writeCoverageReport', or 'silentCoverageReport'.
  -}
  }

-- | Print a coverage report to stdout using prettyprinter.
printCoverageReport :: CoverageReport -> IO ()
printCoverageReport = print . Pretty.pretty

-- | Write a coverage report to a file.
writeCoverageReport :: FilePath -> CoverageReport -> IO ()
writeCoverageReport fp = writeFile fp . show . Pretty.pretty

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
writeCoverageJSON fp = LBS.writeFile fp . Aeson.encode . coverageSummary

-- | Print a coverage report as pretty-printed JSON to stdout.
printCoverageJSONPretty :: CoverageReport -> IO ()
printCoverageJSONPretty = LBS.putStrLn . Aeson.encodePretty . coverageSummary

-- | Write a coverage report as pretty-printed JSON to a file.
writeCoverageJSONPretty :: FilePath -> CoverageReport -> IO ()
writeCoverageJSONPretty fp = LBS.writeFile fp . Aeson.encodePretty . coverageSummary

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
