module Convex.Tasty.Streaming.Types (
  Event (..),
  TestInfo (..),
  TestOutcome (..),
  FailureInfo (..),
) where

import Convex.Tasty.Streaming.SrcLoc (SrcLocRange, groupRanges, ungroupRanges)
import Convex.Tasty.Streaming.TMSummary (ThreatModelSummary)
import Data.Aeson (FromJSON (..), ToJSON (..), Value, object, withObject, (.:), (.:?), (.=))
import Data.Aeson.Types (Pair)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | Information about a single test in the tree
data TestInfo = TestInfo
  { tiId :: !Int
  , tiName :: !Text
  , tiPath :: ![Text]
  , tiSrcLoc :: !(Maybe SrcLocRange)
  {- ^ Optional source-location range pointing at the test's definition.
  'Nothing' for tests defined using upstream tasty providers without our shims.
  -}
  }
  deriving (Eq, Show, Generic)

instance ToJSON TestInfo where
  toJSON (TestInfo i n p mloc) =
    object $
      [ "id" .= i
      , "name" .= n
      , "path" .= p
      ]
        <> maybe [] (\l -> ["srcLoc" .= l]) mloc

instance FromJSON TestInfo where
  parseJSON = withObject "TestInfo" $ \o ->
    TestInfo
      <$> o .: "id"
      <*> o .: "name"
      <*> o .: "path"
      <*> o .:? "srcLoc"

-- | Outcome of a completed test
data TestOutcome
  = TestSuccess
  | TestFailure !FailureInfo
  deriving (Eq, Show, Generic)

-- | Details about a test failure
data FailureInfo = FailureInfo
  { fiReason :: !Text
  , fiMessage :: !Text
  }
  deriving (Eq, Show, Generic)

instance ToJSON FailureInfo where
  toJSON (FailureInfo r m) =
    object
      [ "reason" .= r
      , "message" .= m
      ]

instance FromJSON FailureInfo where
  parseJSON = withObject "FailureInfo" $ \o ->
    FailureInfo
      <$> o .: "reason"
      <*> o .: "message"

-- | A streaming event emitted as a single NDJSON line
data Event
  = SuiteStarted
      { esPackageRoot :: !(Maybe Text)
      {- ^ Optional absolute path to the cabal package root directory,
      captured at ingredient startup. Consumers can resolve
      @packageRoot + srcLoc.file@ to disambiguate identical
      'srcLocFile' values across packages in multi-package workspaces.
      -}
      , esTests :: ![TestInfo]
      }
  | TestStarted
      { etId :: !Int
      }
  | TestProgress
      { epId :: !Int
      , epMessage :: !Text
      , epPercent :: !Float
      }
  | TestDone
      { edId :: !Int
      , edOutcome :: !TestOutcome
      , edDuration :: !Double
      , edDescription :: !Text
      , edThreatModel :: !(Maybe ThreatModelSummary)
      , edUncovered :: ![SrcLocRange]
      }
  | TestTrace
      { ettTestId :: !Int
      , ettCategory :: !Text
      , ettCovered :: ![SrcLocRange]
      , ettTrace :: !Value -- pre-serialized IterationTrace JSON
      }
  | SuiteDone
      { esPassed :: !Int
      , esFailed :: !Int
      , esDuration :: !Double
      }
  deriving (Eq, Show, Generic)

instance ToJSON Event where
  toJSON (SuiteStarted mRoot ts) =
    object $
      [ "event" .= ("suite_started" :: Text)
      , "tests" .= ts
      ]
        <> maybe [] (\r -> ["packageRoot" .= r]) mRoot
  toJSON (TestStarted i) =
    object
      [ "event" .= ("test_started" :: Text)
      , "id" .= i
      ]
  toJSON (TestProgress i msg pct) =
    object
      [ "event" .= ("test_progress" :: Text)
      , "id" .= i
      , "message" .= msg
      , "percent" .= pct
      ]
  toJSON (TestDone i outcome dur desc mTm uncov) =
    object $
      [ "event" .= ("test_done" :: Text)
      , "id" .= i
      , "duration" .= dur
      , "description" .= desc
      , "uncovered" .= groupRanges uncov
      ]
        <> outcomeFields outcome
        <> threatModelFields mTm
   where
    outcomeFields TestSuccess = ["success" .= True]
    outcomeFields (TestFailure fi) =
      [ "success" .= False
      , "failure" .= fi
      ]
    threatModelFields :: Maybe ThreatModelSummary -> [Pair]
    threatModelFields = maybe [] (\s -> ["threat_model" .= s])
  toJSON (TestTrace i cat cov trace) =
    object
      [ "event" .= ("test_trace" :: Text)
      , "id" .= i
      , "category" .= cat
      , "trace" .= trace
      , "covered" .= groupRanges cov
      ]
  toJSON (SuiteDone p f dur) =
    object
      [ "event" .= ("suite_done" :: Text)
      , "passed" .= p
      , "failed" .= f
      , "duration" .= dur
      ]

instance FromJSON Event where
  parseJSON = withObject "Event" $ \o -> do
    tag :: Text <- o .: "event"
    case tag of
      "suite_started" ->
        SuiteStarted
          <$> o .:? "packageRoot"
          <*> o .: "tests"
      "test_started" ->
        TestStarted <$> o .: "id"
      "test_progress" ->
        TestProgress
          <$> o .: "id"
          <*> o .: "message"
          <*> o .: "percent"
      "test_done" -> do
        eid <- o .: "id"
        dur <- o .: "duration"
        desc <- o .: "description"
        success <- o .: "success"
        outcome <-
          if success
            then pure TestSuccess
            else TestFailure <$> o .: "failure"
        mTm <- o .:? "threat_model"
        uncov <- ungroupRanges <$> o .: "uncovered"
        pure (TestDone eid outcome dur desc mTm uncov)
      "test_trace" ->
        TestTrace
          <$> o .: "id"
          <*> o .: "category"
          <*> (ungroupRanges <$> o .: "covered")
          <*> o .: "trace"
      "suite_done" ->
        SuiteDone
          <$> o .: "passed"
          <*> o .: "failed"
          <*> o .: "duration"
      other -> fail ("Unknown event tag: " <> show other)
