{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Convex.SchemaGen (
  -- * Schema generation
  streamingEventSchema,
) where

import Control.Lens hiding (allOf, (.=))
import Data.Aeson ((.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.HashMap.Strict.InsOrd qualified as InsOrdHashMap
import Data.OpenApi
import Data.OpenApi.Declare
import Data.OpenApi.Lens qualified as L
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import Data.Text qualified as Text

-- Types from convex-tasty-streaming
import Convex.Tasty.Streaming.TMSummary (ThreatModelSummary (..))
import Convex.Tasty.Streaming.Types (
  Event (..),
  FailureInfo (..),
  MonitoringClassStat (..),
  MonitoringLabelStat (..),
  MonitoringStats (..),
  MonitoringTableEntry (..),
  MonitoringTableStat (..),
  TestInfo (..),
  TestOutcome (..),
 )

-- Types from convex-testing-interface
import Convex.TestingInterface.Trace (
  AssetSummary (..),
  IterationStatus (..),
  IterationTrace (..),
  TestCategory (..),
  TestRunTrace (..),
  ThreatModelTrace (..),
  ThreatModelTraceOutcome (..),
  Transition (..),
  TransitionResult (..),
  TxInputSummary (..),
  TxOutputSummary (..),
  TxSummary (..),
  ValueSummary (..),
 )
import Convex.ThreatModel.TxModifier (TxMod (..))

{- | The complete schema for a single NDJSON streaming event line.
This is the root schema — each line of output is one Event.
-}
streamingEventSchema :: Aeson.Value
streamingEventSchema =
  let (defs, _eventRef) = runDeclare (declareSchemaRef (Proxy @Event)) (mempty :: Definitions Schema)
      -- Serialize all definitions to JSON and fix $ref paths
      defsJson = fmap (fixRefs . Aeson.toJSON) defs
      -- Get the Event schema to extract its oneOf for root level
      eventSchema = case InsOrdHashMap.lookup "Event" defs of
        Just s -> fixRefs (Aeson.toJSON s)
        Nothing -> Aeson.object []
      -- Extract oneOf from Event schema for the root
      rootOneOf = case eventSchema of
        Aeson.Object o -> case KeyMap.lookup "oneOf" o of
          Just v -> v
          Nothing -> Aeson.Array mempty
        _ -> Aeson.Array mempty
   in Aeson.object
        [ "$schema" .= ("https://json-schema.org/draft/2020-12/schema" :: Text)
        , "$id" .= ("https://github.com/j-mueller/sc-tools/streaming-events.schema.json" :: Text)
        , "title" .= ("SC-Tools Streaming Event" :: Text)
        , "description" .= ("A single NDJSON line from the sc-tools test streaming reporter" :: Text)
        , "oneOf" .= rootOneOf
        , "$defs" .= InsOrdHashMap.toHashMap defsJson
        ]

-- | Recursively replace "#/components/schemas/" with "#/$defs/" in all $ref values
fixRefs :: Aeson.Value -> Aeson.Value
fixRefs (Aeson.Object o) = Aeson.Object $
  KeyMap.map fixRefs $
    case KeyMap.lookup "$ref" o of
      Just (Aeson.String ref) ->
        KeyMap.insert "$ref" (Aeson.String (Text.replace "#/components/schemas/" "#/$defs/" ref)) o
      _ -> o
fixRefs (Aeson.Array a) = Aeson.Array $ fmap fixRefs a
fixRefs v = v

-- ============================================================
-- ToSchema instances for convex-tasty-streaming types
-- ============================================================

instance ToSchema TestInfo where
  declareNamedSchema _ = do
    -- srcLoc is an optional object with all-required inner fields.
    -- When omitted, the test was defined using upstream tasty providers
    -- (without our Convex.Tasty.HUnit / Convex.Tasty.QuickCheck shims).
    let srcLocSchema =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("file", Inline $ mempty & type_ ?~ OpenApiString)
                , ("startLine", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("startCol", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("endLine", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("endCol", Inline $ mempty & type_ ?~ OpenApiInteger)
                ]
            & required .~ ["file", "startLine", "startCol", "endLine", "endCol"]
    pure $
      NamedSchema (Just "TestInfo") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("id", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("path", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject (Inline $ mempty & type_ ?~ OpenApiString))
              , ("srcLoc", Inline srcLocSchema) -- optional: key absent when test definition site is unknown
              ]
          & required .~ ["id", "name", "path"]

instance ToSchema FailureInfo where
  declareNamedSchema _ = do
    pure $
      NamedSchema (Just "FailureInfo") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("reason", Inline $ mempty & type_ ?~ OpenApiString)
              , ("message", Inline $ mempty & type_ ?~ OpenApiString)
              ]
          & required .~ ["reason", "message"]

instance ToSchema ThreatModelSummary where
  declareNamedSchema _ = do
    pure $
      NamedSchema (Just "ThreatModelSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("tested", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("total", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("passed", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("failed", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("skipped", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("errors", Inline $ mempty & type_ ?~ OpenApiInteger)
              ]
          & required .~ ["name", "tested", "total", "passed", "failed", "skipped", "errors"]

instance ToSchema MonitoringLabelStat where
  declareNamedSchema _ =
    pure $
      NamedSchema (Just "MonitoringLabelStat") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("labels", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject (Inline $ mempty & type_ ?~ OpenApiString))
              , ("count", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("percent", Inline $ mempty & type_ ?~ OpenApiNumber & format ?~ "double")
              ]
          & required .~ ["labels", "count", "percent"]

instance ToSchema MonitoringClassStat where
  declareNamedSchema _ =
    pure $
      NamedSchema (Just "MonitoringClassStat") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("count", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("percent", Inline $ mempty & type_ ?~ OpenApiNumber & format ?~ "double")
              ]
          & required .~ ["name", "count", "percent"]

instance ToSchema MonitoringTableEntry where
  declareNamedSchema _ =
    pure $
      NamedSchema (Just "MonitoringTableEntry") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("value", Inline $ mempty & type_ ?~ OpenApiString)
              , ("count", Inline $ mempty & type_ ?~ OpenApiInteger)
              ]
          & required .~ ["value", "count"]

instance ToSchema MonitoringTableStat where
  declareNamedSchema _ = do
    entryRef <- declareSchemaRef (Proxy @MonitoringTableEntry)
    pure $
      NamedSchema (Just "MonitoringTableStat") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("entries", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject entryRef)
              ]
          & required .~ ["name", "entries"]

instance ToSchema MonitoringStats where
  declareNamedSchema _ = do
    labelRef <- declareSchemaRef (Proxy @MonitoringLabelStat)
    classRef <- declareSchemaRef (Proxy @MonitoringClassStat)
    tableRef <- declareSchemaRef (Proxy @MonitoringTableStat)
    pure $
      NamedSchema (Just "MonitoringStats") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("numTests", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("numDiscarded", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("labels", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject labelRef)
              , ("classes", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject classRef)
              , ("tables", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject tableRef)
              ]
          & required .~ ["numTests", "numDiscarded", "labels", "classes", "tables"]

instance ToSchema Event where
  declareNamedSchema _ = do
    testInfoRef <- declareSchemaRef (Proxy @TestInfo)
    failureInfoRef <- declareSchemaRef (Proxy @FailureInfo)
    threatModelSummaryRef <- declareSchemaRef (Proxy @ThreatModelSummary)
    monitoringStatsRef <- declareSchemaRef (Proxy @MonitoringStats)
    iterationTraceRef <- declareSchemaRef (Proxy @IterationTrace)

    let suiteStarted =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["suite_started"])
                , ("packageRoot", Inline $ mempty & type_ ?~ OpenApiString) -- optional: absolute path to cabal package root
                , ("tests", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject testInfoRef)
                ]
            & required .~ ["event", "tests"]

    let testStarted =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["test_started"])
                , ("id", Inline $ mempty & type_ ?~ OpenApiInteger)
                ]
            & required .~ ["event", "id"]

    let testProgress =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["test_progress"])
                , ("id", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("message", Inline $ mempty & type_ ?~ OpenApiString)
                , ("percent", Inline $ mempty & type_ ?~ OpenApiNumber & format ?~ "float")
                ]
            & required .~ ["event", "id", "message", "percent"]

    -- TestDone is complex: TestOutcome is inlined (success: bool + optional failure)
    -- threat_model is optional (key absent when Nothing)
    let testDone =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["test_done"])
                , ("id", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("duration", Inline $ mempty & type_ ?~ OpenApiNumber & format ?~ "double")
                , ("description", Inline $ mempty & type_ ?~ OpenApiString)
                , ("success", Inline $ mempty & type_ ?~ OpenApiBoolean)
                , ("failure", failureInfoRef) -- optional, absent when success=true
                , ("threat_model", threatModelSummaryRef) -- optional, absent when not applicable
                , ("monitoring_stats", monitoringStatsRef) -- optional, absent when quickcheck wrapper is not used
                ]
            & required .~ ["event", "id", "duration", "description", "success"]

    -- TestTrace: trace is Value (pre-serialized IterationTrace)
    let testTrace =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["test_trace"])
                , ("id", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("category", Inline $ mempty & type_ ?~ OpenApiString)
                , ("trace", iterationTraceRef) -- pre-serialized but matches IterationTrace schema
                ]
            & required .~ ["event", "id", "category", "trace"]

    let suiteDone =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("event", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["suite_done"])
                , ("passed", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("failed", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("duration", Inline $ mempty & type_ ?~ OpenApiNumber & format ?~ "double")
                ]
            & required .~ ["event", "passed", "failed", "duration"]

    pure $
      NamedSchema (Just "Event") $
        mempty
          & oneOf ?~ [Inline suiteStarted, Inline testStarted, Inline testProgress, Inline testDone, Inline testTrace, Inline suiteDone]
          & discriminator ?~ Discriminator "event" mempty

-- ============================================================
-- ToSchema instances for convex-testing-interface types
-- ============================================================

instance ToSchema AssetSummary where
  declareNamedSchema _ = do
    pure $
      NamedSchema (Just "AssetSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("policyId", Inline $ mempty & type_ ?~ OpenApiString)
              , ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("quantity", Inline $ mempty & type_ ?~ OpenApiInteger)
              ]
          & required .~ ["policyId", "name", "quantity"]

instance ToSchema ValueSummary where
  declareNamedSchema _ = do
    assetRef <- declareSchemaRef (Proxy @AssetSummary)
    pure $
      NamedSchema (Just "ValueSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("lovelace", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("assets", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject assetRef)
              ]
          & required .~ ["lovelace", "assets"]

instance ToSchema TxInputSummary where
  declareNamedSchema _ = do
    valueRef <- declareSchemaRef (Proxy @ValueSummary)
    pure $
      NamedSchema (Just "TxInputSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("utxo", Inline $ mempty & type_ ?~ OpenApiString)
              , ("address", Inline $ mempty & type_ ?~ OpenApiString)
              , ("value", valueRef)
              ]
          & required .~ ["utxo", "address", "value"]

instance ToSchema TxOutputSummary where
  declareNamedSchema _ = do
    valueRef <- declareSchemaRef (Proxy @ValueSummary)
    pure $
      NamedSchema (Just "TxOutputSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("utxo", Inline $ mempty & type_ ?~ OpenApiString)
              , ("address", Inline $ mempty & type_ ?~ OpenApiString)
              , ("value", valueRef)
              , ("datum", Inline $ mempty & type_ ?~ OpenApiString & nullable ?~ True) -- key present, value null when no datum
              ]
          & required .~ ["utxo", "address", "value", "datum"]

instance ToSchema TxSummary where
  declareNamedSchema _ = do
    inputRef <- declareSchemaRef (Proxy @TxInputSummary)
    outputRef <- declareSchemaRef (Proxy @TxOutputSummary)
    valueRef <- declareSchemaRef (Proxy @ValueSummary)
    pure $
      NamedSchema (Just "TxSummary") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("id", Inline $ mempty & type_ ?~ OpenApiString & nullable ?~ True)
              , ("inputs", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject inputRef)
              , ("outputs", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject outputRef)
              , ("mint", Inline $ mempty & nullable ?~ True & allOf ?~ [valueRef]) -- nullable ref
              , ("fee", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("signers", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject (Inline $ mempty & type_ ?~ OpenApiString))
              , ("validRange", Inline $ mempty & type_ ?~ OpenApiString & nullable ?~ True)
              ]
          & required .~ ["id", "inputs", "outputs", "mint", "fee", "signers", "validRange"]

instance ToSchema TransitionResult where
  declareNamedSchema _ = do
    let success =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["success"])
                , ("txId", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "txId"]
    let failure =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["failure"])
                , ("error", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "error"]
    pure $
      NamedSchema (Just "TransitionResult") $
        mempty
          & oneOf ?~ [Inline success, Inline failure]
          & discriminator ?~ Discriminator "status" mempty

instance ToSchema Transition where
  declareNamedSchema _ = do
    txRef <- declareSchemaRef (Proxy @TxSummary)
    resultRef <- declareSchemaRef (Proxy @TransitionResult)
    pure $
      NamedSchema (Just "Transition") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("stepIndex", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("action", Inline $ mempty & type_ ?~ OpenApiString)
              , ("stateBefore", Inline mempty) -- opaque JSON (user model state)
              , ("stateAfter", Inline mempty) -- opaque JSON (user model state)
              , ("transaction", Inline $ mempty & nullable ?~ True & allOf ?~ [txRef]) -- nullable ref
              , ("result", resultRef)
              ]
          & required .~ ["stepIndex", "action", "stateBefore", "stateAfter", "transaction", "result"]

instance ToSchema IterationStatus where
  declareNamedSchema _ = do
    let success =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["success"])]
            & required .~ ["status"]
    let failure =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["failure"])
                , ("message", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "message"]
    let discarded =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["discarded"])
                , ("message", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "message"]
    pure $
      NamedSchema (Just "IterationStatus") $
        mempty
          & oneOf ?~ [Inline success, Inline failure, Inline discarded]
          & discriminator ?~ Discriminator "status" mempty

instance ToSchema ThreatModelTraceOutcome where
  declareNamedSchema _ = do
    let passed =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["passed"])]
            & required .~ ["status"]
    let failed =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["failed"])
                , ("reason", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "reason"]
    let skipped =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["skipped"])
                , ("reason", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "reason"]
    let err =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("status", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["error"])
                , ("message", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["status", "message"]
    pure $
      NamedSchema (Just "ThreatModelTraceOutcome") $
        mempty
          & oneOf ?~ [Inline passed, Inline failed, Inline skipped, Inline err]
          & discriminator ?~ Discriminator "status" mempty

instance ToSchema TxMod where
  declareNamedSchema _ = do
    valueRef <- declareSchemaRef (Proxy @ValueSummary)
    let nullableString = Inline $ mempty & type_ ?~ OpenApiString & nullable ?~ True
    let nullableValue = Inline $ mempty & nullable ?~ True & allOf ?~ [valueRef]

    let removeInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["removeInput"])
                , ("utxo", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "utxo"]

    let removeOutput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["removeOutput"])
                , ("index", Inline $ mempty & type_ ?~ OpenApiInteger)
                ]
            & required .~ ["type", "index"]

    let changeOutput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["changeOutput"])
                , ("index", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("address", nullableString)
                , ("value", nullableValue)
                , ("datum", nullableString)
                , ("referenceScript", nullableString)
                ]
            & required .~ ["type", "index", "address", "value", "datum", "referenceScript"]

    let changeInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["changeInput"])
                , ("utxo", Inline $ mempty & type_ ?~ OpenApiString)
                , ("address", nullableString)
                , ("value", nullableValue)
                , ("datum", nullableString)
                , ("referenceScript", nullableString)
                ]
            & required .~ ["type", "utxo", "address", "value", "datum", "referenceScript"]

    let changeScriptInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["changeScriptInput"])
                , ("utxo", Inline $ mempty & type_ ?~ OpenApiString)
                , ("value", nullableValue)
                , ("datum", nullableString)
                , ("redeemer", nullableString)
                , ("referenceScript", nullableString)
                ]
            & required .~ ["type", "utxo", "value", "datum", "redeemer", "referenceScript"]

    let changeValidityRange =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["changeValidityRange"])
                , ("lowerBound", nullableString)
                , ("upperBound", nullableString)
                ]
            & required .~ ["type", "lowerBound", "upperBound"]

    let addOutput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addOutput"])
                , ("address", Inline $ mempty & type_ ?~ OpenApiString)
                , ("value", valueRef)
                , ("datum", nullableString)
                , ("referenceScript", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "address", "value", "datum", "referenceScript"]

    let addInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addInput"])
                , ("address", Inline $ mempty & type_ ?~ OpenApiString)
                , ("value", valueRef)
                , ("datum", nullableString)
                , ("referenceScript", Inline $ mempty & type_ ?~ OpenApiString)
                , ("isReferenceInput", Inline $ mempty & type_ ?~ OpenApiBoolean)
                ]
            & required .~ ["type", "address", "value", "datum", "referenceScript", "isReferenceInput"]

    let addReferenceScriptInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addReferenceScriptInput"])
                , ("scriptHash", Inline $ mempty & type_ ?~ OpenApiString)
                , ("value", valueRef)
                , ("datum", nullableString)
                , ("redeemer", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "scriptHash", "value", "datum", "redeemer"]

    let addPlutusScriptInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addPlutusScriptInput"])
                , ("value", valueRef)
                , ("datum", nullableString)
                , ("redeemer", Inline $ mempty & type_ ?~ OpenApiString)
                , ("referenceScript", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "value", "datum", "redeemer", "referenceScript"]

    let addPlutusScriptReferenceInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addPlutusScriptReferenceInput"])
                , ("value", valueRef)
                , ("datum", nullableString)
                , ("referenceScript", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "value", "datum", "referenceScript"]

    let addSimpleScriptInput =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addSimpleScriptInput"])
                , ("value", valueRef)
                , ("referenceScript", Inline $ mempty & type_ ?~ OpenApiString)
                , ("isReferenceInput", Inline $ mempty & type_ ?~ OpenApiBoolean)
                ]
            & required .~ ["type", "value", "referenceScript", "isReferenceInput"]

    let addPlutusScriptMint =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["addPlutusScriptMint"])
                , ("assetName", Inline $ mempty & type_ ?~ OpenApiString)
                , ("quantity", Inline $ mempty & type_ ?~ OpenApiInteger)
                , ("redeemer", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "assetName", "quantity", "redeemer"]

    let removeRequiredSigner =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [ ("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["removeRequiredSigner"])
                , ("keyHash", Inline $ mempty & type_ ?~ OpenApiString)
                ]
            & required .~ ["type", "keyHash"]

    let replaceTx =
          mempty
            & type_ ?~ OpenApiObject
            & properties
              .~ InsOrdHashMap.fromList
                [("type", Inline $ mempty & type_ ?~ OpenApiString & enum_ ?~ ["replaceTx"])]
            & required .~ ["type"]

    pure $
      NamedSchema (Just "TxMod") $
        mempty
          & oneOf
            ?~ map
              Inline
              [ removeInput
              , removeOutput
              , changeOutput
              , changeInput
              , changeScriptInput
              , changeValidityRange
              , addOutput
              , addInput
              , addReferenceScriptInput
              , addPlutusScriptInput
              , addPlutusScriptReferenceInput
              , addSimpleScriptInput
              , addPlutusScriptMint
              , removeRequiredSigner
              , replaceTx
              ]
          & discriminator ?~ Discriminator "type" mempty

instance ToSchema ThreatModelTrace where
  declareNamedSchema _ = do
    txRef <- declareSchemaRef (Proxy @TxSummary)
    outcomeRef <- declareSchemaRef (Proxy @ThreatModelTraceOutcome)
    txModRef <- declareSchemaRef (Proxy @TxMod)
    pure $
      NamedSchema (Just "ThreatModelTrace") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("name", Inline $ mempty & type_ ?~ OpenApiString)
              , ("targetTxIndex", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("modifications", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject txModRef)
              , ("originalTx", txRef)
              , ("modifiedTx", Inline $ mempty & nullable ?~ True & allOf ?~ [txRef])
              , ("outcome", outcomeRef)
              ]
          & required .~ ["name", "targetTxIndex", "modifications", "originalTx", "modifiedTx", "outcome"]

instance ToSchema IterationTrace where
  declareNamedSchema _ = do
    statusRef <- declareSchemaRef (Proxy @IterationStatus)
    transitionRef <- declareSchemaRef (Proxy @Transition)
    threatRef <- declareSchemaRef (Proxy @ThreatModelTrace)
    pure $
      NamedSchema (Just "IterationTrace") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("index", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("status", statusRef)
              , ("transitions", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject transitionRef)
              , ("threatModels", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject threatRef)
              ]
          & required .~ ["index", "status", "transitions", "threatModels"]

instance ToSchema TestCategory where
  declareNamedSchema _ = do
    pure $
      NamedSchema (Just "TestCategory") $
        mempty
          & type_ ?~ OpenApiString
          & enum_ ?~ ["positive", "negative"]

instance ToSchema TestRunTrace where
  declareNamedSchema _ = do
    categoryRef <- declareSchemaRef (Proxy @TestCategory)
    iterationRef <- declareSchemaRef (Proxy @IterationTrace)
    pure $
      NamedSchema (Just "TestRunTrace") $
        mempty
          & type_ ?~ OpenApiObject
          & properties
            .~ InsOrdHashMap.fromList
              [ ("testId", Inline $ mempty & type_ ?~ OpenApiInteger)
              , ("testName", Inline $ mempty & type_ ?~ OpenApiString)
              , ("path", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject (Inline $ mempty & type_ ?~ OpenApiString))
              , ("category", categoryRef)
              , ("iterations", Inline $ mempty & type_ ?~ OpenApiArray & items ?~ OpenApiItemsObject iterationRef)
              ]
          & required .~ ["testId", "testName", "path", "category", "iterations"]
