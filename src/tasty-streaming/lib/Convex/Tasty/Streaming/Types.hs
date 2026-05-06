module Convex.Tasty.Streaming.Types (
  Event (..),
  TestInfo (..),
  TestOutcome (..),
  FailureInfo (..),
) where

import Convex.Tasty.Streaming.TMSummary (ThreatModelSummary)
import Data.Aeson (ToJSON (..), Value, object, (.=))
import Data.Aeson.Types (Pair)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | Information about a single test in the tree
data TestInfo = TestInfo
  { tiId :: !Int
  , tiName :: !Text
  , tiPath :: ![Text]
  }
  deriving (Eq, Show, Generic)

instance ToJSON TestInfo where
  toJSON (TestInfo i n p) =
    object
      [ "id" .= i
      , "name" .= n
      , "path" .= p
      ]

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

-- | A streaming event emitted as a single NDJSON line
data Event
  = SuiteStarted
      { esTests :: ![TestInfo]
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
      }
  | TestTrace
      { ettTestId :: !Int
      , ettCategory :: !Text
      , ettTrace :: !Value -- pre-serialized IterationTrace JSON
      }
  | SuiteDone
      { esPassed :: !Int
      , esFailed :: !Int
      , esDuration :: !Double
      }
  deriving (Eq, Show, Generic)

instance ToJSON Event where
  toJSON (SuiteStarted ts) =
    object
      [ "event" .= ("suite_started" :: Text)
      , "tests" .= ts
      ]
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
  toJSON (TestDone i outcome dur desc mTm) =
    object $
      [ "event" .= ("test_done" :: Text)
      , "id" .= i
      , "duration" .= dur
      , "description" .= desc
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
  toJSON (TestTrace i cat trace) =
    object
      [ "event" .= ("test_trace" :: Text)
      , "id" .= i
      , "category" .= cat
      , "trace" .= trace
      ]
  toJSON (SuiteDone p f dur) =
    object
      [ "event" .= ("suite_done" :: Text)
      , "passed" .= p
      , "failed" .= f
      , "duration" .= dur
      ]
