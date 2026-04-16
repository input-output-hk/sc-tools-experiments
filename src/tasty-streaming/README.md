# convex-tasty-streaming

A Tasty ingredient that streams test results as **NDJSON** (newline-delimited JSON) to stdout. Designed for consumption by IDE extensions, VS Code test explorers, and external tooling that need real-time structured test output.

## Integration

### 1. Add the dependency

In your `.cabal` file, add `convex-tasty-streaming` to the test suite's `build-depends`:

```cabal
test-suite my-tests
  build-depends:
    , convex-tasty-streaming
    , tasty
    ...
```

### 2. Replace `defaultMain`

In your test entry point, swap `defaultMain` for `defaultMainStreaming`:

```haskell
-- Before
import Test.Tasty (defaultMain)

main :: IO ()
main = defaultMain tests

-- After
import Convex.Tasty.Streaming (defaultMainStreaming)

main :: IO ()
main = defaultMainStreaming tests
```

`defaultMainStreaming` behaves identically to `defaultMain` by default. The streaming features are only activated when their CLI flags are passed. Normal console output is unchanged.

If you use a wrapper like `withCoverage`, just replace the `defaultMain` call inside it:

```haskell
main :: IO ()
main = withCoverage config $ \opts runOpts ->
  defaultMainStreaming (tests opts runOpts)
```

### 3. Add the package to `cabal.project`

```
packages:
  src/tasty-streaming
  ...
```

## Usage

### Discover tests (no execution)

List the full test tree as structured JSON without running any tests:

```bash
cabal test convex-testing-interface-test --test-options="--list-tests-json"
```

Combine with Tasty's `-p` pattern flag to filter:

```bash
cabal test convex-testing-interface-test --test-options="--list-tests-json -p 'ping-pong'"
```

### Stream test results

Run tests with real-time NDJSON output instead of console output:

```bash
cabal test convex-testing-interface-test --test-options="--streaming-json"
```

Combine with pattern filtering:

```bash
cabal test convex-testing-interface-test --test-options="--streaming-json -p 'ping-pong'"
```

## NDJSON Event Schema

Each line of output is a self-contained JSON object with an `event` field. Events are emitted in this order:

| Event            | When                           | Fields                                                          |
|------------------|--------------------------------|-----------------------------------------------------------------|
| `suite_started`  | Before any test runs           | `tests[]` — array of `{id, name, path}`                        |
| `test_started`   | A test begins executing        | `id`                                                            |
| `test_done`      | A test completes               | `id`, `success`, `duration`, `description`, optional `failure`  |
| `suite_done`     | After all tests finish         | `passed`, `failed`, `duration`                                  |

### `suite_started`

```json
{
  "event": "suite_started",
  "tests": [
    {"id": 0, "name": "First bid equals minimum bid", "path": ["auction tests", "unit tests"]},
    {"id": 1, "name": "Positive tests", "path": ["auction tests", "property-based tests"]}
  ]
}
```

- `id` — stable integer index, used to correlate `test_started` and `test_done` events
- `name` — the test's own name (leaf label in the Tasty tree)
- `path` — ordered list of group names from root to the test's parent

### `test_started`

```json
{"event": "test_started", "id": 0}
```

Emitted when the test transitions from queued to executing.

### `test_done`

Success:

```json
{"event": "test_done", "id": 0, "success": true, "duration": 0.217, "description": "First bid equals minimum bid"}
```

Failure:

```json
{
  "event": "test_done",
  "id": 1,
  "success": false,
  "duration": 0.456,
  "description": "Positive tests",
  "failure": {
    "reason": "TestFailed",
    "message": "Expected 1 but got 2"
  }
}
```

### `suite_done`

```json
{"event": "suite_done", "passed": 55, "failed": 0, "duration": 79.6}
```

## Parsing with jq

Since `cabal test` prints its own non-JSON lines to stdout (build info, "Running 1 test suites...", etc.), use this pattern to safely parse only the JSON lines:

```bash
jq -R 'fromjson? // empty'
```

This reads each line as a raw string (`-R`), tries to parse it as JSON (`fromjson?` — the `?` silently skips failures), and discards any leftovers (`// empty`).

### Examples

**Pretty-print all events:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--streaming-json" 2>/dev/null \
  | jq -R 'fromjson? // empty'
```

**List the test tree (discovery only):**

```bash
cabal test convex-testing-interface-test \
  --test-options="--list-tests-json" 2>/dev/null \
  | jq -R 'fromjson? // empty | .tests[] | {id, name, path}'
```

**Show only failures:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--streaming-json" 2>/dev/null \
  | jq -R 'fromjson? // empty | select(.event == "test_done" and .success == false)'
```

**Extract test names and durations as a table:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--streaming-json" 2>/dev/null \
  | jq -r -R 'fromjson? // empty | select(.event == "test_done") | [.id, .duration, .description] | @tsv'
```

**Get the final summary:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--streaming-json" 2>/dev/null \
  | jq -R 'fromjson? // empty | select(.event == "suite_done")'
```

**Count tests per top-level group:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--list-tests-json" 2>/dev/null \
  | jq -R 'fromjson? // empty | .tests | group_by(.path[0]) | map({group: .[0].path[0], count: length})'
```

**Filter discovery by path:**

```bash
cabal test convex-testing-interface-test \
  --test-options="--list-tests-json -p 'ping-pong'" 2>/dev/null \
  | jq -R 'fromjson? // empty | .tests[] | {id, name, path}'
```

## API Reference

| Export                     | Type         | Description                                                          |
|----------------------------|--------------|----------------------------------------------------------------------|
| `defaultMainStreaming`     | `TestTree -> IO ()` | Drop-in replacement for `defaultMain` with streaming support   |
| `streamingJsonReporter`    | `Ingredient` | The `--streaming-json` reporter (real-time NDJSON during test runs)   |
| `listTestsJsonIngredient`  | `Ingredient` | The `--list-tests-json` manager (test discovery without execution)   |
| `streamingIngredients`     | `[Ingredient]` | All ingredients combined (listing + JSON discovery + streaming + console) |
