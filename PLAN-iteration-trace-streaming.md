# Plan: Iteration Trace Streaming for VS Code Extension

## Context & Goal

The `sc-tools` project has a property-based testing framework (`convex-testing-interface`) for Cardano smart contracts, and a streaming NDJSON reporter (`convex-tasty-streaming`) that emits test events consumed by a VS Code extension.

**Current state:** The streaming emits high-level events (`suite_started`, `test_started`, `test_done`, `suite_done`) with aggregate `ThreatModelSummary` (just counts). This is sufficient for a test runner UI but not for debugging.

**Goal:** Enable the VS Code extension to visually display:
1. **State transitions** — For each QuickCheck iteration, show the sequence of actions performed, the model state before/after each action, and the transaction produced.
2. **Threat model details** — For each transaction in an iteration, show how a threat model modified it, what the modified tx looks like, and whether the ledger accepted/rejected it.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  TestingInterface framework (propRunActionsWithOptions)           │
│  Already controls: initialize → runActions loop → threat models  │
│  We instrument HERE (invisible to user)                          │
└───────────────────────────────┬──────────────────────────────────┘
                                │ produces
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Trace Data Types (new module: Convex.TestingInterface.Trace)     │
│  Pure Haskell types with ToJSON instances                         │
│  Delivery-agnostic: just data                                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │ stored in
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Trace Store (new module: Convex.TestingInterface.Trace.Store)    │
│  Thread-safe IORef-based store, same pattern as TMStore           │
│  Keyed by Tasty test path                                        │
└───────────────────────────────┬──────────────────────────────────┘
                                │ read by
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Streaming Layer (extends convex-tasty-streaming)                 │
│  New event type `iteration_trace` emitted after `test_done`      │
│  Or: written to sidecar file referenced in `test_done`           │
└──────────────────────────────────────────────────────────────────┘
```

## Data Types

### File: `src/testing-interface/lib/Convex/TestingInterface/Trace.hs`

```haskell
module Convex.TestingInterface.Trace
  ( TestRunTrace(..)
  , TestCategory(..)
  , IterationTrace(..)
  , IterationStatus(..)
  , Transition(..)
  , TransitionResult(..)
  , TxSummary(..)
  , TxInputSummary(..)
  , TxOutputSummary(..)
  , ThreatModelTrace(..)
  , ThreatModelTraceOutcome(..)
  ) where

import Data.Aeson (ToJSON(..), object, (.=))
import Data.Text (Text)
import Cardano.Api qualified as C

-- | Complete trace of a test run (one QuickCheck property = N iterations)
data TestRunTrace = TestRunTrace
  { trtTestId    :: !Int          -- Tasty test ID (links to Event stream's test_done)
  , trtTestName  :: !Text         -- e.g. "Positive tests"
  , trtPath      :: ![Text]       -- e.g. ["MyContract", "Positive tests"]
  , trtCategory  :: !TestCategory
  , trtIterations :: ![IterationTrace]
  }

data TestCategory = Positive | Negative
  deriving (Eq, Show)

-- | Trace of a single QuickCheck iteration
data IterationTrace = IterationTrace
  { itIndex       :: !Int              -- 0-based iteration number
  , itSeed        :: !Int              -- QuickCheck seed for reproducibility
  , itStatus      :: !IterationStatus
  , itTransitions :: ![Transition]     -- ordered action sequence
  , itThreatModels :: ![ThreatModelTrace]  -- threat model results for this iteration's txs
  }

data IterationStatus
  = IterationSuccess
  | IterationFailure !Text     -- error message
  | IterationDiscarded !Text   -- reason it was discarded
  deriving (Eq, Show)

-- | One step in the iteration: action → state change → transaction
data Transition = Transition
  { trStepIndex   :: !Int
  , trAction      :: !Text           -- Show of the Action value
  , trStateBefore :: !Value          -- ToJSON of model state before perform
  , trStateAfter  :: !Value          -- ToJSON of model state after perform
  , trTransaction :: !(Maybe TxSummary)  -- Nothing if perform failed before building tx
  , trResult      :: !TransitionResult
  }

data TransitionResult
  = TransitionSuccess !Text    -- TxId as text
  | TransitionFailure !Text    -- BalanceTxError description
  deriving (Eq, Show)

-- | Compact representation of a transaction for visualization
data TxSummary = TxSummary
  { txsId         :: !(Maybe Text)       -- TxId if submitted, Nothing if not
  , txsInputs     :: ![TxInputSummary]
  , txsOutputs    :: ![TxOutputSummary]
  , txsMint       :: !(Maybe Text)       -- Rendered value if non-zero mint
  , txsFee        :: !Integer            -- Lovelace fee
  , txsSigners    :: ![Text]             -- Required signer key hashes
  , txsValidRange :: !(Maybe Text)       -- Rendered validity interval
  }

data TxInputSummary = TxInputSummary
  { tisRef     :: !Text    -- "txid#index"
  , tisAddress :: !Text    -- Bech32 or hex
  , tisValue   :: !Text    -- Rendered value (ada + tokens)
  }

data TxOutputSummary = TxOutputSummary
  { tosIndex   :: !Int
  , tosAddress :: !Text
  , tosValue   :: !Text
  , tosDatum   :: !(Maybe Text)  -- "inline:<hash>" or "hash:<hash>" or Nothing
  }

-- | What happened when a threat model was applied to one of this iteration's txs
data ThreatModelTrace = ThreatModelTrace
  { tmtName           :: !Text
  , tmtTargetTxIndex  :: !Int              -- index into itTransitions
  , tmtModifications  :: ![Text]           -- human-readable mod descriptions
  , tmtOriginalTx     :: !TxSummary
  , tmtModifiedTx     :: !(Maybe TxSummary)  -- Nothing if modification couldn't produce a valid tx body
  , tmtOutcome        :: !ThreatModelTraceOutcome
  }

data ThreatModelTraceOutcome
  = TMTOPassed            -- modified tx was rejected (good!)
  | TMTOFailed !Text      -- modified tx was ACCEPTED (vulnerability found)
  | TMTOSkipped !Text     -- couldn't test (rebalancing failed, precondition unmet)
  | TMTOError !Text       -- unexpected error
  deriving (Eq, Show)
```

All types get `ToJSON` instances. The JSON schema should be:

```json
{
  "testId": 3,
  "testName": "Positive tests",
  "path": ["MyContract", "Positive tests"],
  "category": "positive",
  "iterations": [
    {
      "index": 0,
      "seed": 12345,
      "status": "success",
      "transitions": [
        {
          "stepIndex": 0,
          "action": "Deposit (Wallet 1) (Value 50000000)",
          "stateBefore": {"balance": 0, "owner": "addr_test1..."},
          "stateAfter": {"balance": 50000000, "owner": "addr_test1..."},
          "transaction": {
            "id": "abc123...",
            "inputs": [{"ref": "def456...#0", "address": "addr_test1...", "value": "100 ADA"}],
            "outputs": [{"index": 0, "address": "addr_test1...", "value": "50 ADA", "datum": "inline:abc..."}],
            "mint": null,
            "fee": 200000,
            "signers": ["abc123..."],
            "validRange": "[0, +inf)"
          },
          "result": {"status": "success", "txId": "abc123..."}
        }
      ],
      "threatModels": [
        {
          "name": "unprotectedScriptOutput",
          "targetTxIndex": 0,
          "modifications": ["Changed output #0 value: removed 10 ADA"],
          "originalTx": { "..." : "..." },
          "modifiedTx": { "..." : "..." },
          "outcome": {"status": "passed"}
        }
      ]
    }
  ]
}
```

### File: `src/testing-interface/lib/Convex/TestingInterface/Trace/Store.hs`

```haskell
module Convex.TestingInterface.Trace.Store
  ( TraceStore
  , TraceRecorder(..)
  , TraceStoreOption(..)
  , newTraceStore
  , storeTraceRecorder
  , lookupTrace
  , lookupAllTraces
  ) where

-- | Thread-safe store for iteration traces, keyed by test path.
newtype TraceStore = TraceStore (IORef (Map String [IterationTrace]))

-- | Recorder closure passed to test bodies via Tasty option system.
-- Default is no-op (when streaming is not active).
newtype TraceRecorder = TraceRecorder
  { recordIteration :: String -> IterationTrace -> IO ()
  }

instance IsOption TraceRecorder where
  defaultValue = TraceRecorder (\_ _ -> pure ())
  -- ...

newtype TraceStoreOption = TraceStoreOption (Maybe TraceStore)

instance IsOption TraceStoreOption where
  defaultValue = TraceStoreOption Nothing
  -- ...

newTraceStore :: IO TraceStore
storeTraceRecorder :: TraceStore -> TraceRecorder
lookupTrace :: TraceStore -> String -> IO (Maybe [IterationTrace])
lookupAllTraces :: TraceStore -> IO (Map String [IterationTrace])
```

## Implementation: Recording Traces (Invisible to User)

### Constraint Change

In `Convex.TestingInterface`:

```haskell
-- BEFORE:
class (Show state, Eq state, Show (Action state)) => TestingInterface state where

-- AFTER:
class (Show state, Eq state, Show (Action state), ToJSON state) => TestingInterface state where
```

This is the ONLY user-facing change. Users must add `ToJSON` to their state type and `deriving (Generic)` + `instance ToJSON MyState` (or hand-write it).

### Instrumenting `runActions`

The current `runActions` loop:

```haskell
runActions :: (TestingInterface state, MonadIO m) => RunOptions -> Int -> state -> TestingMonadT (PropertyM m) state
runActions _ 0 s = pure s
runActions opts i s = do
  mAction <- lift $ genAction s
  case mAction of
    Just action -> runAction opts s action >>= runActions opts (i - 1)
    Nothing -> pure s
```

We create a new variant `runActionsTraced` that accumulates `[Transition]`:

```haskell
runActionsTraced
  :: (TestingInterface state, MonadIO m)
  => RunOptions
  -> Int
  -> state
  -> TestingMonadT (PropertyM m) (state, [Transition])
runActionsTraced opts maxActions initialState = go 0 initialState []
  where
    go stepIdx state acc
      | stepIdx >= maxActions = pure (state, reverse acc)
      | otherwise = do
          mAction <- lift $ genAction state
          case mAction of
            Nothing -> pure (state, reverse acc)
            Just action -> do
              let stateBefore = toJSON state
                  actionText = Text.pack (show action)
              -- Snapshot tx count before perform
              txCountBefore <- getTxCount
              -- Run the action
              result <- tryPerform state action
              case result of
                Right newState -> do
                  let stateAfter = toJSON newState
                  -- Get the tx that was just submitted (if any)
                  mTxSummary <- getLastSubmittedTxSummary txCountBefore
                  let txId = maybe Nothing txsId mTxSummary
                      transition = Transition
                        { trStepIndex = stepIdx
                        , trAction = actionText
                        , trStateBefore = stateBefore
                        , trStateAfter = stateAfter
                        , trTransaction = mTxSummary
                        , trResult = TransitionSuccess (fromMaybe "" txId)
                        }
                  go (stepIdx + 1) newState (transition : acc)
                Left err -> do
                  let transition = Transition
                        { trStepIndex = stepIdx
                        , trAction = actionText
                        , trStateBefore = stateBefore
                        , trStateAfter = stateBefore  -- state unchanged on failure
                        , trTransaction = Nothing
                        , trResult = TransitionFailure (Text.pack (show err))
                        }
                  -- For positive tests, a failure here means the iteration fails
                  pure (state, reverse (transition : acc))
```

Key helpers needed:

```haskell
-- Get number of successfully submitted txs so far
getTxCount :: (MonadMockchain era m) => m Int
getTxCount = length . mcsTransactions <$> getMockChainState

-- Get the tx submitted since txCountBefore, summarize it
getLastSubmittedTxSummary :: (MonadMockchain era m) => Int -> m (Maybe TxSummary)
getLastSubmittedTxSummary countBefore = do
  state <- getMockChainState
  let txs = mcsTransactions state
      newTxs = drop countBefore txs
  case newTxs of
    ((validatedTx, _) : _) -> pure (Just (summarizeTx validatedTx (mcsPoolState state)))
    [] -> pure Nothing

-- Try to perform, catching BalanceTxError
tryPerform :: (TestingInterface state, MonadIO m)
  => state -> Action state -> TestingMonadT (PropertyM m) (Either (BalanceTxError ConwayEra) state)
```

### Instrumenting `positiveTest`

In the existing `positiveTest` function, replace:
```haskell
finalState <- runActions opts 10 initialState
```
with:
```haskell
(finalState, transitions) <- runActionsTraced opts 10 initialState
```

Then after running threat models, construct the `IterationTrace`:
```haskell
let iterTrace = IterationTrace
      { itIndex = iterationNumber  -- need to thread this through
      , itSeed = seed              -- from QuickCheck
      , itStatus = IterationSuccess
      , itTransitions = transitions
      , itThreatModels = threatModelTraces  -- built from tmResults (see below)
      }
```

And record it:
```haskell
case mTraceRecorder of
  Just recorder -> liftIO $ recordIteration recorder testKey iterTrace
  Nothing -> pure ()
```

### Instrumenting Threat Model Runner

The current `runThreatModelCheck` returns `ThreatModelOutcome`. We need a richer version that also returns trace data.

Create `runThreatModelCheckTraced`:

```haskell
data ThreatModelStepTrace = ThreatModelStepTrace
  { tmstTargetTxIndex :: !Int
  , tmstModifications :: ![Text]      -- from TxModifier
  , tmstOriginalTx    :: !TxSummary
  , tmstModifiedTx    :: !(Maybe TxSummary)
  , tmstValidationResult :: !ThreatModelTraceOutcome
  }

runThreatModelCheckTraced
  :: (MonadMockchain Era m, MonadFail m, MonadIO m)
  => SigningWallet
  -> ThreatModel a
  -> [ThreatModelEnv]
  -> m (ThreatModelOutcome, [ThreatModelStepTrace])
```

This wraps the existing `runThreatModelCheck` logic but additionally:
1. When `Validate mods k` is encountered: records the `mods` as `[Text]` (pretty-print each `TxMod`), summarizes the original tx from `ThreatModelEnv.currentTx`, summarizes the modified tx after `applyTxModifier`
2. Accumulates these into a list alongside the outcome

The pretty-printing of `TxMod` values uses the existing `Convex.ThreatModel.Pretty` module (or extends it).

### Converting ThreatModelStepTrace → ThreatModelTrace

After running all threat models for an iteration:

```haskell
buildThreatModelTraces :: [(Text, ThreatModelOutcome, [ThreatModelStepTrace])] -> [ThreatModelTrace]
buildThreatModelTraces results =
  [ ThreatModelTrace
      { tmtName = name
      , tmtTargetTxIndex = tmstTargetTxIndex step
      , tmtModifications = tmstModifications step
      , tmtOriginalTx = tmstOriginalTx step
      , tmtModifiedTx = tmstModifiedTx step
      , tmtOutcome = mapOutcome outcome
      }
  | (name, outcome, steps) <- results
  , step <- steps  -- one ThreatModelTrace per step (per tx tested)
  ]
```

### Building TxSummary

```haskell
-- File: src/testing-interface/lib/Convex/TestingInterface/Trace/TxSummary.hs

summarizeTx :: C.Tx C.ConwayEra -> C.UTxO C.ConwayEra -> TxSummary
summarizeTx tx utxo =
  let body = C.getTxBody tx
      C.TxBody content = body
      txId = C.getTxId body
      inputs = ... -- resolve from utxo
      outputs = ... -- from txBodyContent
      mint = ... -- from txMintValue content
      fee = ... -- from txFee content
      signers = ... -- from txExtraKeyWits content
      validRange = ... -- from txValidityLowerBound/txValidityUpperBound
  in TxSummary { ... }
```

## Streaming: Delivering Traces to the Extension

### New Event Type

Add to `Convex.Tasty.Streaming.Types`:

```haskell
data Event
  = ...existing constructors...
  | IterationTraceEvent
      { iteTestId :: !Int
      , iteIteration :: !IterationTrace  -- from Convex.TestingInterface.Trace
      }
```

**However**, this creates a dependency from `convex-tasty-streaming` on `convex-testing-interface` which is undesirable (circular or heavyweight).

### Better: Agnostic Serialized Blob

Instead, the streaming layer treats iteration traces as opaque JSON `Value`:

```haskell
data Event
  = ...existing constructors...
  | TestTrace
      { ettTestId :: !Int
      , ettCategory :: !Text       -- "positive" | "negative"
      , ettTrace :: !Value         -- pre-serialized JSON (the IterationTrace)
      }
```

The `convex-tasty-streaming` package only needs `aeson` (already a dep). The `convex-testing-interface` package serializes `IterationTrace` to `Value` before storing.

### Store & Recorder (in convex-tasty-streaming)

Extend the existing TMStore pattern:

```haskell
-- In Convex.Tasty.Streaming.TMSummary (or new module Convex.Tasty.Streaming.TraceStore)

newtype TraceStore = TraceStore (IORef (Map String [Value]))
  -- Key: test path string, Value: list of serialized IterationTrace JSON values

newtype TraceRecorder = TraceRecorder
  { trRecordIteration :: String -> Value -> IO ()
  }

instance IsOption TraceRecorder where
  defaultValue = TraceRecorder (\_ _ -> pure ())
  optionName = Tagged "trace-recorder"
  optionHelp = Tagged "internal: iteration trace recorder"

newtype TraceStoreOption = TraceStoreOption (Maybe TraceStore)

instance IsOption TraceStoreOption where
  defaultValue = TraceStoreOption Nothing
  optionName = Tagged "trace-store"
  optionHelp = Tagged "internal: iteration trace store handle"
```

### Emission Strategy

Two options (implement the pragmatic one first):

**Option A: Emit after each iteration (real-time).**
The testing-interface code calls `trRecordIteration` after each QuickCheck iteration. The recorder immediately emits an NDJSON line:

```json
{"event": "test_trace", "id": 3, "category": "positive", "iteration": {...}}
```

This gives the extension real-time updates as iterations complete.

**Option B: Emit all at test_done time.**
Store all iteration traces, then when the streaming reporter emits `test_done`, also emit all traces for that test. Simpler but no real-time feedback.

**Recommendation: Option A** — real-time is much better for the VS Code UX (user sees iterations appearing live).

### Implementation in convex-tasty-streaming

The `TraceRecorder` directly emits (it holds a reference to the output lock):

```haskell
-- In Convex.Tasty.Streaming (the reporter module)

-- When setting up the streaming reporter:
let traceRecorder = TraceRecorder $ \key iterationJson -> do
      -- Find the test ID for this key
      let testId = lookupTestIdByKey testMap key
      withMVar outputLock $ \_ ->
        emitEvent $ TestTrace
          { ettTestId = testId
          , ettCategory = -- determined from key
          , ettTrace = iterationJson
          }
```

But wait — the test body doesn't know the Tasty test ID. The recorder needs to map test keys to IDs.

**Solution:** The recorder is constructed by the reporter (which has the test map). The test body uses a logical key (like "MyContract/Positive tests"), and the recorder resolves it to the numeric ID.

### Wiring in defaultMainStreaming

```haskell
defaultMainStreaming :: TestTree -> IO ()
defaultMainStreaming tree = do
  tmStore <- newTMStore
  traceStore <- newTraceStore  -- NEW
  outputLock <- newMVar ()     -- shared lock
  let traceRec = streamingTraceRecorder traceStore outputLock  -- NEW
  let tree' =
        localOption (TMStoreOption (Just tmStore)) $
          localOption (storeRecorder tmStore) $
            localOption (TraceStoreOption (Just traceStore)) $  -- NEW
              localOption traceRec $                              -- NEW
                tree
  defaultMainWithIngredients streamingIngredients tree'
```

### How the Testing Interface Gets the Recorder

In `propRunActionsWithOptions`, access the recorder via Tasty's `askOption`:

```haskell
-- The test property needs access to the TraceRecorder.
-- Tasty options are available in the test tree construction.
-- We use `askOption` pattern:

positiveTest :: ... -> TraceRecorder -> Property
positiveTest opts traceRecorder tms evs = monadicIO $ do
  ...
  -- After building IterationTrace:
  liftIO $ trRecordIteration traceRecorder testKey (toJSON iterTrace)
```

The `propRunActionsWithOptions` function uses `askOption` to retrieve the `TraceRecorder`:

```haskell
propRunActionsWithOptions groupName opts =
  askOption $ \(traceRecorder :: TraceRecorder) ->
    ... existing test tree construction, passing traceRecorder to positiveTest ...
```

## File Structure (New/Modified Files)

### New Files

| File | Package | Purpose |
|------|---------|---------|
| `src/testing-interface/lib/Convex/TestingInterface/Trace.hs` | convex-testing-interface | Data types + ToJSON instances |
| `src/testing-interface/lib/Convex/TestingInterface/Trace/TxSummary.hs` | convex-testing-interface | TxSummary builder (summarizeTx) |
| `src/tasty-streaming/lib/Convex/Tasty/Streaming/TraceStore.hs` | convex-tasty-streaming | TraceStore, TraceRecorder, TraceStoreOption |

### Modified Files

| File | Changes |
|------|---------|
| `src/testing-interface/lib/Convex/TestingInterface.hs` | Add `ToJSON state` constraint, create `runActionsTraced`, modify `positiveTest`/`negativeTest` to build and record traces, accept `TraceRecorder` |
| `src/testing-interface/lib/Convex/ThreatModel.hs` | Add `runThreatModelCheckTraced` alongside existing `runThreatModelCheck` |
| `src/testing-interface/convex-testing-interface.cabal` | Add new exposed modules, add `aeson` dep (already there) |
| `src/tasty-streaming/lib/Convex/Tasty/Streaming.hs` | Wire TraceStore/TraceRecorder, emit `test_trace` events |
| `src/tasty-streaming/lib/Convex/Tasty/Streaming/Types.hs` | Add `TestTrace` constructor to `Event` |
| `src/tasty-streaming/convex-tasty-streaming.cabal` | Add new exposed module |

## Implementation Order

1. **Phase 1: Data types** — Create `Convex.TestingInterface.Trace` with all types and ToJSON instances. No behavioral changes yet. Compiles independently.

2. **Phase 2: TxSummary builder** — Create `summarizeTx` and helpers. Test with a simple unit test that builds a tx and summarizes it.

3. **Phase 3: Traced runner** — Create `runActionsTraced` and `runThreatModelCheckTraced`. These are NEW functions alongside the existing ones (no breaking changes to existing behavior).

4. **Phase 4: Wire into positiveTest/negativeTest** — Modify the test property functions to use traced variants and build `IterationTrace`. Pass `TraceRecorder` through.

5. **Phase 5: TraceStore + streaming** — Create `TraceStore` module, extend Event type, wire into `defaultMainStreaming`.

6. **Phase 6: Integration test** — Run an existing test suite with `--streaming-json` and verify the new `test_trace` events appear with correct structure.

## Design Principles

1. **User sees no change** except adding `ToJSON` to their state type. All recording is internal to the framework.
2. **Existing behavior preserved** — `runActions` still exists unchanged. The traced variant is used only when a `TraceRecorder` is active (not no-op default).
3. **Delivery-agnostic data** — The `Trace` types know nothing about streaming, stdout, or VS Code. They're just data with JSON serialization.
4. **No spaghetti** — Each concern is in its own module. The data types are in `Trace.hs`, the tx summarization in `TxSummary.hs`, the store in `TraceStore.hs`, the recording in the framework's existing control flow.
5. **Performance guard** — When `TraceRecorder` is the default no-op, zero overhead (no JSON serialization happens). The `toJSON` calls only execute when streaming is active.

## Key Decisions Made

- **Threat models are nested in positive iterations** — because they reuse the same transactions. No separate iteration concept for threat models.
- **`ToJSON state` required** — structured data is essential for the extension to render diffs and tables.
- **Real-time emission** — traces are emitted per-iteration as they complete, not batched at test end.
- **Opaque `Value` in streaming layer** — `convex-tasty-streaming` doesn't depend on `convex-testing-interface`; it just passes pre-serialized JSON.
- **`test_trace` is a new event type** — keeps backward compatibility (old consumers ignore unknown events).

## JSON Event Stream Example (Full)

A complete streaming session would look like:

```
{"event":"suite_started","tests":[{"id":1,"name":"Positive tests","path":["MyContract","Positive tests"]},{"id":2,"name":"Negative tests","path":["MyContract","Negative tests"]},{"id":3,"name":"unprotectedScriptOutput","path":["MyContract","Threat models","unprotectedScriptOutput"]}]}
{"event":"test_started","id":1}
{"event":"test_trace","id":1,"category":"positive","iteration":{"index":0,"seed":42,"status":"success","transitions":[...],"threatModels":[...]}}
{"event":"test_trace","id":1,"category":"positive","iteration":{"index":1,"seed":43,"status":"success","transitions":[...],"threatModels":[...]}}
... (100 iterations) ...
{"event":"test_done","id":1,"success":true,"duration":5.2,"description":"OK, passed 100 tests"}
{"event":"test_started","id":2}
{"event":"test_trace","id":2,"category":"negative","iteration":{"index":0,"seed":44,"status":"success","transitions":[...],"threatModels":[]}}
... 
{"event":"test_done","id":2,"success":true,"duration":3.1,"description":"OK, passed 100 tests"}
{"event":"test_started","id":3}
{"event":"test_done","id":3,"success":true,"duration":0.01,"description":"Passed (147 tested, 147 passed)","threat_model":{"name":"unprotectedScriptOutput","tested":147,"total":147,"passed":147,"failed":0,"skipped":0,"errors":0}}
{"event":"suite_done","passed":3,"failed":0,"duration":8.4}
```

## Negative Test Trace Shape

For negative tests, the trace shows:
- The valid prefix (transitions that succeeded)
- The invalid action attempt (last transition with `TransitionFailure`)

```json
{
  "index": 5,
  "seed": 99,
  "status": "success",
  "transitions": [
    {"stepIndex": 0, "action": "Deposit w1 50₳", "stateBefore": {...}, "stateAfter": {...}, "transaction": {...}, "result": {"status": "success", "txId": "..."}},
    {"stepIndex": 1, "action": "Deposit w2 30₳", "stateBefore": {...}, "stateAfter": {...}, "transaction": {...}, "result": {"status": "success", "txId": "..."}},
    {"stepIndex": 2, "action": "Withdraw w1 200₳ [INVALID - violates precondition]", "stateBefore": {...}, "stateAfter": {...}, "transaction": null, "result": {"status": "failure", "error": "InsufficientFunds ..."}}
  ],
  "threatModels": []
}
```

## Edge Cases to Handle

1. **perform succeeds but submits no tx** (e.g., off-chain state update only) → `trTransaction = Nothing`, `trResult = TransitionSuccess ""`
2. **perform submits multiple txs** (rare but possible) → capture only the last one, or extend to list (start with last-only for simplicity)
3. **Threat model tests multiple envs** (iterates through txs) → one `ThreatModelTrace` entry per env tested, or aggregate. Start with per-env for maximum visibility.
4. **Large state types** → The JSON could be large. Consider adding a max-size guard or truncation in the streaming layer (future optimization).
5. **QuickCheck seed** → Available via `replay` option or by capturing it from the QC internals. May need to use `withMaxSuccess` + explicit seed tracking.

## Dependencies (Package Changes)

### convex-testing-interface.cabal additions:
```
exposed-modules:
  ...existing...
  Convex.TestingInterface.Trace
  Convex.TestingInterface.Trace.TxSummary
```
No new package dependencies needed (already has `aeson`, `cardano-api`, `text`, `containers`).

### convex-tasty-streaming.cabal additions:
```
exposed-modules:
  ...existing...
  Convex.Tasty.Streaming.TraceStore
```
No new package dependencies needed (already has `aeson`, `containers`).
