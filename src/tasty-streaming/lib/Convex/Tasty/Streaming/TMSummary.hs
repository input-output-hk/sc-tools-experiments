{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Convex.Tasty.Streaming.TMSummary (
  ThreatModelSummary (..),
  TMStore,
  TMRecorder (..),
  TMStoreOption (..),
  newTMStore,
  storeRecorder,
  lookupThreatModelSummary,
) where

import Data.Aeson (FromJSON (..), ToJSON (..), object, withObject, (.:), (.=))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Tagged (Tagged (..))
import Data.Text (Text)
import GHC.Generics (Generic)
import Test.Tasty.Options (IsOption (..))

-- | Structured summary of a threat-model test case.
data ThreatModelSummary = ThreatModelSummary
  { tmsName :: !Text
  , tmsTested :: !Int
  , tmsTotal :: !Int
  , tmsPassed :: !Int
  , tmsFailed :: !Int
  , tmsSkipped :: !Int
  , tmsErrors :: !Int
  }
  deriving (Show, Eq, Generic)

instance ToJSON ThreatModelSummary where
  toJSON s =
    object
      [ "name" .= tmsName s
      , "tested" .= tmsTested s
      , "total" .= tmsTotal s
      , "passed" .= tmsPassed s
      , "failed" .= tmsFailed s
      , "skipped" .= tmsSkipped s
      , "errors" .= tmsErrors s
      ]

instance FromJSON ThreatModelSummary where
  parseJSON = withObject "ThreatModelSummary" $ \o ->
    ThreatModelSummary
      <$> o .: "name"
      <*> o .: "tested"
      <*> o .: "total"
      <*> o .: "passed"
      <*> o .: "failed"
      <*> o .: "skipped"
      <*> o .: "errors"

-- | Mutable storage for threat-model summaries, owned by the reporter.
newtype TMStore = TMStore (IORef (Map String ThreatModelSummary))

{- | A recorder closure passed to test bodies via Tasty's option system.
The default no-op makes summaries silently dropped when the streaming
reporter is not active.
-}
newtype TMRecorder = TMRecorder
  { tmRecord :: String -> ThreatModelSummary -> IO ()
  }

{- | Internal option carrying the live store. Set by `defaultMainStreaming`
alongside the recorder so the reporter can read summaries back out.
-}
newtype TMStoreOption = TMStoreOption (Maybe TMStore)

instance IsOption TMRecorder where
  defaultValue = TMRecorder (\_ _ -> pure ())
  parseValue = const Nothing
  optionName = Tagged "tm-recorder"
  optionHelp = Tagged "internal: threat-model summary recorder"

instance IsOption TMStoreOption where
  defaultValue = TMStoreOption Nothing
  parseValue = const Nothing
  optionName = Tagged "tm-store"
  optionHelp = Tagged "internal: threat-model summary store handle"

-- | Allocate fresh storage. Call once per reporter run.
newTMStore :: IO TMStore
newTMStore = TMStore <$> newIORef Map.empty

-- | Build a recorder that writes into the given store.
storeRecorder :: TMStore -> TMRecorder
storeRecorder (TMStore ref) = TMRecorder $ \key s ->
  atomicModifyIORef' ref $ \m -> (Map.insert key s m, ())

-- | Look up a summary by key (does not delete).
lookupThreatModelSummary :: TMStore -> String -> IO (Maybe ThreatModelSummary)
lookupThreatModelSummary (TMStore ref) key =
  Map.lookup key <$> readIORef ref
