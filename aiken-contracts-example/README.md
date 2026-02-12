# Aiken Validators for sc-tools Testing

Aiken smart contracts used to prove that `convex-testing-interface`
can test Aiken-compiled (non-PlutusTx) smart contracts.

## Validators

### 1. `validators/check_answer.ak` — Simple spending validator

Checks that `datum + redeemer == 43`.

- **Datum:** `Option<Int>` (inline datum, an integer)
- **Redeemer:** `Int` (an integer)
- **Blueprint key:** `check_answer.check_answer.spend`

Example: locking with datum `10` and spending with redeemer `33` succeeds
because `10 + 33 = 43`.

### 2. `validators/ping_pong.ak` — Secure stateful PingPong validator

A state machine that transitions between `Pinged`, `Ponged`, and `Stopped`.

- **Datum:** `Option<State>` where `State { Pinged, Ponged, Stopped }`
- **Redeemer:** `Action` where `Action { Ping, Pong, Stop }`
- **Blueprint key:** `ping_pong.ping_pong.spend`

Valid transitions:
- `Pinged` + `Pong` → `Ponged`
- `Ponged` + `Ping` → `Pinged`
- `Pinged` or `Ponged` + `Stop` → `Stopped`

Security checks (matching the Haskell secure version):
1. Continuation output must go to the **same script address** (prevents output redirect attack)
2. Output **value must equal input value** (prevents large value attack)
3. Aiken's `expect` rejects unknown constructors (prevents large data attack)

Wire compatibility: The Aiken types encode identically to the Haskell types
(`Constr 0/1/2 []`), so the Haskell test suite reuses `PingPongState` and
`PingPongRedeemer` directly.

## Prerequisites

[Aiken](https://aiken-lang.org/installation-instructions) v1.1.x or later.

Install via cargo:

```bash
cargo install aiken --locked
```

Or via aikup:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://install.aiken-lang.org | sh
aikup
```

## Build

```bash
aiken build
```

This produces `plutus.json` — a [CIP-0057 Plutus blueprint](https://github.com/cardano-foundation/CIPs/pull/258)
containing the compiled UPLC code and validator hashes for all validators.

## Update the test fixture

After modifying any validator, rebuild and update the blueprint used by
`convex-testing-interface` tests:

```bash
./update-blueprint.sh
```

Or manually:

```bash
aiken build
cp plutus.json ../src/testing-interface/test/data/aiken-contracts-example.json
```

Then re-run the Haskell tests to verify:

```bash
cabal test convex-testing-interface
```

## How it integrates with sc-tools

The Haskell test suite loads the blueprint JSON at test time using
`Convex.Aiken.Blueprint.loadFromFile`, extracts `PlutusScript PlutusScriptV3`
for each validator by key, and uses them with the standard `BuildTx` functions —
the exact same functions used for PlutusTx/Plinth scripts.

Test modules:
- `test/AikenSpec.hs` — check_answer unit tests (4 tests)
- `test/AikenPingPongSpec.hs` — ping_pong unit tests (9), TestingInterface property test, threat model tests (579 lines)
