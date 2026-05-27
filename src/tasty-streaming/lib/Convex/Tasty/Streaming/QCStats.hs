{-# LANGUAGE NamedFieldPuns #-}

module Convex.Tasty.Streaming.QCStats (
  QCStatsStore,
  QCStatsRecorder (..),
  QCStatsStoreOption (..),
  newQCStatsStore,
  storeQCStatsRecorder,
  lookupQCStats,
  lookupQCStatsBySrcLoc,
  recordQCStatsFromState,
) where

import Convex.Tasty.Streaming.SrcLoc (SrcLocRange (..))
import Convex.Tasty.Streaming.Types (
  MonitoringClassStat (..),
  MonitoringLabelStat (..),
  MonitoringStats (..),
  MonitoringTableEntry (..),
  MonitoringTableStat (..),
 )
import Data.Foldable (for_)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (sortOn)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Ord (Down (..))
import Data.Tagged (Tagged (..))
import Data.Text qualified as T
import Test.QuickCheck.State qualified as QS
import Test.Tasty.Options (IsOption (..))

newtype QCStatsStore = QCStatsStore (IORef (Map String MonitoringStats))

newtype QCStatsRecorder = QCStatsRecorder
  { qcRecordStats :: String -> MonitoringStats -> IO ()
  }

newtype QCStatsStoreOption = QCStatsStoreOption (Maybe QCStatsStore)

instance IsOption QCStatsRecorder where
  defaultValue = QCStatsRecorder (\_ _ -> pure ())
  parseValue = const Nothing
  optionName = Tagged "qc-stats-recorder"
  optionHelp = Tagged "internal: quickcheck monitoring stats recorder"

instance IsOption QCStatsStoreOption where
  defaultValue = QCStatsStoreOption Nothing
  parseValue = const Nothing
  optionName = Tagged "qc-stats-store"
  optionHelp = Tagged "internal: quickcheck monitoring stats store handle"

newQCStatsStore :: IO QCStatsStore
newQCStatsStore = QCStatsStore <$> newIORef Map.empty

storeQCStatsRecorder :: QCStatsStore -> QCStatsRecorder
storeQCStatsRecorder (QCStatsStore ref) = QCStatsRecorder $ \key stats ->
  atomicModifyIORef' ref $ \m -> (Map.insert key stats m, ())

lookupQCStats :: QCStatsStore -> String -> IO (Maybe MonitoringStats)
lookupQCStats (QCStatsStore ref) key =
  Map.lookup key <$> readIORef ref

lookupQCStatsBySrcLoc :: QCStatsStore -> SrcLocRange -> IO (Maybe MonitoringStats)
lookupQCStatsBySrcLoc store loc =
  lookupQCStats store (srcLocKey loc)

recordQCStatsFromState :: QCStatsRecorder -> Maybe SrcLocRange -> QS.State -> IO ()
recordQCStatsFromState recorder mLoc st =
  for_ mLoc $ \loc ->
    qcRecordStats recorder (srcLocKey loc) (fromState st)

srcLocKey :: SrcLocRange -> String
srcLocKey SrcLocRange{slrFile, slrStartLine, slrStartCol, slrEndLine, slrEndCol} =
  T.unpack slrFile
    <> ":"
    <> show slrStartLine
    <> ":"
    <> show slrStartCol
    <> ":"
    <> show slrEndLine
    <> ":"
    <> show slrEndCol

fromState :: QS.State -> MonitoringStats
fromState st =
  MonitoringStats
    { msNumTests = total
    , msNumDiscarded = QS.numDiscardedTests st
    , msLabels =
        sortOn
          (Down . mlsCount)
          [ MonitoringLabelStat
              { mlsLabels = map T.pack names
              , mlsCount = count
              , mlsPercent = pct count
              }
          | (names, count) <- Map.toList (QS.labels st)
          ]
    , msClasses =
        sortOn
          (Down . mcsCount)
          [ MonitoringClassStat
              { mcsName = T.pack className
              , mcsCount = count
              , mcsPercent = pct count
              }
          | (className, count) <- Map.toList (QS.classes st)
          ]
    , msTables =
        [ MonitoringTableStat
            { mtsName = T.pack tableName
            , mtsEntries =
                sortOn
                  (Down . mteCount)
                  [ MonitoringTableEntry
                      { mteValue = T.pack entryName
                      , mteCount = count
                      }
                  | (entryName, count) <- Map.toList tableEntries
                  ]
            }
        | (tableName, tableEntries) <- Map.toList (QS.tables st)
        ]
    }
 where
  total = QS.numSuccessTests st
  pct count
    | total <= 0 = 0
    | otherwise = (fromIntegral count * 100) / fromIntegral total
