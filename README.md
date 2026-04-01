# sc-testing-tools

Property-based testing and threat modeling for Cardano smart contracts.

## What This Repository Is

This repository provides `convex-testing-interface`, a property-based testing
framework for Cardano smart contracts. It was originally forked from
[sc-tools](https://github.com/input-output-hk/sc-tools), but has since become a
standalone library that depends on sc-tools packages externally via
`source-repository-package` declarations. All commits prior to the split
represent original sc-tools work.

The single package in this repository, `convex-testing-interface`, offers:

- **Property-based testing** using QuickCheck for stateful smart contract interactions
- **Generic threat models** with 15 built-in security tests (double satisfaction, datum hijacking, token forgery, and more)
- **Coverage tracking** for Plutus script execution paths

The framework is built for Plinth but is capable of testing contracts written
in any language that compiles to Plutus Core, including Aiken. It builds on top
of the sc-tools mockchain emulator, allowing fast, deterministic testing without
running a cardano-node.

## Getting Started

### Prerequisites

This project has only been tested using the Nix development shell. To enter it:

```bash
nix develop
```

This provides GHC 9.6.6, Cabal 3.10.3.0, and all required system dependencies.
Building outside of Nix is not officially supported.

### Adding as a Dependency

To use `convex-testing-interface` in your project, add the following to your
`cabal.project`:

```cabal
source-repository-package
  type: git
  location: https://github.com/input-output-hk/sc-testing-tools.git
  tag: <commit-hash>
  subdir:
    src/testing-interface
```

The testing interface depends on several sc-tools packages. Add these as well:

```cabal
source-repository-package
  type: git
  location: https://github.com/input-output-hk/sc-tools.git
  tag: <commit-hash>
  subdir:
    src/base
    src/coin-selection
    src/mockchain
    src/node-client
    src/optics
    src/wallet
```

Then add the dependency to your `.cabal` file:

```cabal
build-depends: convex-testing-interface
```

### Building and Testing

For developing this repository itself:

```bash
nix develop
cabal build all
cabal test all
```

## TestingInterface: Property-Based Testing for Smart Contracts

The `convex-testing-interface` package provides a QuickCheck-based framework
for testing Cardano smart contracts. You define a model of your contract's
behavior, generate arbitrary action sequences, and the framework verifies that the
on-chain behavior matches your model.

### The Core Idea

Property-based testing for smart contracts works by:

1. **Modeling** your contract's state as a Haskell type
2. **Generating** arbitrary sequences of actions (deposits, withdrawals, state transitions)
3. **Executing** those actions on the mockchain
4. **Verifying** the on-chain state matches your model after each action

This catches edge cases that manual tests miss: race conditions, unexpected
orderings, and boundary conditions.

### The TestingInterface Typeclass

```haskell
class (Show state, Eq state) => TestingInterface state where
  -- Required: define what actions are possible
  data Action state

  -- Required: deploy your contract, return initial model state
  initialize :: (MonadIO m) => TestingMonadT m state

  -- Required: generate random actions based on current state
  arbitraryAction :: state -> Gen (Action state)

  -- Required: pure state transition (your model)
  nextState :: state -> Action state -> state

  -- Required: execute an action on the mockchain
  perform :: (MonadIO m) => state -> Action state -> TestingMonadT m ()

  -- Optional: filter out invalid actions before execution
  precondition :: state -> Action state -> Bool
  precondition _ _ = True

  -- Optional: verify on-chain state matches model after each action
  validate :: (MonadIO m) => state -> TestingMonadT m Bool
  validate _ = pure True

  -- Optional: add QuickCheck labels/counters for test coverage
  monitoring :: state -> Action state -> Property -> Property
  monitoring _ _ = id

  -- Threat model testing (covered in the next section)
  threatModels :: [ThreatModel ()]
  expectedVulnerabilities :: [ThreatModel ()]
```

The `TestingMonadT` gives you access to `MonadBlockchain`,
`MonadMockchain`, and `MonadIO`, giving access to the mockchain,
blockchain queries, and IO.

### Minimal Example

Here is a sketch showing the pattern. For a complete working example, see
[PingPongSpec.hs](src/testing-interface/test/PingPongSpec.hs).

```haskell
-- Your model: tracks what the on-chain counter should be
data CounterModel = CounterModel
  { counterValue :: Integer
  } deriving (Show, Eq)

instance TestingInterface CounterModel where
  -- Actions users can take
  data Action CounterModel
    = Increment
    | Decrement
    deriving (Show, Eq)

  -- Deploy the counter script with initial value 0
  initialize = do
    let datum = CounterDatum 0
        tx = execBuildTx $
               BuildTx.payToScriptInlineDatum
                 Defaults.networkId
                 counterScriptHash
                 datum
                 C.NoStakeAddress
                 (C.lovelaceToValue 2_000_000)
    void $ tryBalanceAndSubmit mempty Wallet.w1 tx TrailingChange []
    pure $ CounterModel 0

  -- Generate random actions
  arbitraryAction _ = QC.elements [Increment, Decrement]

  -- Can't decrement below zero
  precondition state Decrement = counterValue state > 0
  precondition _ _ = True

  -- Pure model update
  nextState state Increment = state { counterValue = counterValue state + 1 }
  nextState state Decrement = state { counterValue = counterValue state - 1 }

  -- Execute on mockchain
  perform state action = do
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    -- Find script UTxOs, build transaction, submit
    ...

  -- Verify on-chain state matches model
  validate state = do
    utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
    let onChainValue = extractCounterDatum utxoSet
    pure $ onChainValue == counterValue state
```

### The perform Pattern

The `perform` function follows a consistent pattern across all examples:

1. **Get current UTxOs**: `utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo`
2. **Find relevant UTxOs**: Filter for your script address
3. **Build the transaction**: Use `execBuildTx` with `BuildTx` functions
4. **Submit**: `balanceAndSubmit mempty wallet tx TrailingChange []`

The `fromLedgerUTxO` conversion is necessary because `getUtxo` returns ledger
types, but `BuildTx` functions expect `cardano-api` types.

### Running Tests

Use `propRunActions` to generate a test tree with positive, negative, and
threat model tests:

```haskell
import Test.Tasty
import Convex.TestingInterface (propRunActions, propRunActionsWithOptions, RunOptions(..))

tests :: TestTree
tests = testGroup "Counter"
  [ propRunActions @CounterModel "counter operations"
  ]
```

Or with custom options:

```haskell
testsWithOptions :: TestTree
testsWithOptions = testGroup "Counter"
  [ propRunActionsWithOptions @CounterModel "counter operations" opts
  ]
  where
    opts = RunOptions
      { verbose    = True
      , maxActions = 50
      , mcOptions  = Defaults.defaultOptions
      , disableNegativeTesting = Nothing
      }
```

The framework runs three types of tests:

Test suites integrated with `convex-tasty-streaming` support `--streaming-json` (real-time NDJSON output of test results) and `--list-tests-json` (structured JSON test-tree discovery without execution), intended for IDE integrations and external tooling.
See [src/tasty-streaming/README.md](src/tasty-streaming/README.md) for integration instructions, the NDJSON event schema, and `jq` parsing examples.

## Working with cardano node
- **Positive tests**: Valid action sequences should succeed and pass `validate`
- **Negative tests**: Actions that fail `precondition` should be rejected by the validator
- **Threat model tests**: Security checks run after each transaction (covered below)

### Using Plinth Contracts

Scripts compiled with Template Haskell work directly. Coverage tracking is
available through the `withCoverage` helper and `getCovIdx` from `PlutusTx`. See
[PingPongCoverageSpec.hs](src/testing-interface/test/PingPongCoverageSpec.hs)
for a complete coverage example.

### Using Aiken Contracts

Aiken contracts are loaded from their compiled blueprint JSON. Since Aiken and
Plinth use identical CBOR encoding, your Haskell datum/redeemer types work
for both.

```haskell
import Convex.PlutusBlueprint qualified as Blueprint
import Convex.PlutusBlueprint (Blueprint(..))

loadCounterValidator :: IO (C.PlutusScript C.PlutusScriptV3)
loadCounterValidator = do
  path <- Pkg.getDataFileName "test/data/plutus.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "counter.validator.spend" validators of
    Just (C.ScriptInAnyLang
           (C.PlutusScriptLanguage C.PlutusScriptV3)
           (C.PlutusScript _ ps)) -> pure ps
    _ -> fail "counter.validator.spend not found in blueprint"
```

The validator name follows the pattern `module_name.validator_name.purpose`
from your Aiken source. See
[AikenPingPongSpec.hs](src/testing-interface/test/AikenPingPongSpec.hs) for a
complete working example.

### Key Imports

```haskell
import Convex.TestingInterface
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain (fromLedgerUTxO)
import Convex.Class (getUtxo)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.CoinSelection (ChangeOutputPosition(TrailingChange))
import Convex.Wallet.MockWallet qualified as Wallet
import Cardano.Api qualified as C
import Test.Tasty.QuickCheck qualified as QC
```

## Threat Models

Threat models provide automated security testing for smart contracts. After
each successful transaction in a test run, the framework attempts to exploit it
by applying various modifications. If a modified transaction still validates,
the framework has discovered a vulnerability.

The `ThreatModel` monad provides combinators for selecting transaction
elements, applying modifications, and asserting expected outcomes. Each threat
model runs against every transaction produced during property-based testing,
catching vulnerabilities that only manifest under specific conditions.

### Built-in Threat Models

The library ships with 15 generic threat models covering common vulnerability
classes:

**Input/Output Manipulation**
- `doubleSatisfaction` -- Duplicates a script input to check if one output satisfies both
- `unprotectedScriptOutput` -- Redirects continuation outputs to an attacker address
- `inputDuplication` -- Duplicates an existing input in the transaction

**Token and Value Attacks**
- `tokenForgery` / `tokenForgeryAttackWith` -- Attempts unauthorized minting with existing policies
- `valueUnderpaymentAttack` / `valueUnderpaymentAttackWith` -- Reduces value in outputs

**Authorization Bypass**
- `signatoryRemoval` -- Removes required signers from the transaction
- `timeBoundManipulation` -- Widens validity range bounds

**Data Injection**
- `datumByteBloatAttackWith` -- Injects oversized byte string datums
- `largeDataAttackWith` -- Injects data with excessive constructor fields
- `largeValueAttackWith` -- Injects excessive asset entries in values
- `negativeIntegerAttack` -- Replaces integers with negative values
- `duplicateListEntry` -- Adds duplicate entries to lists in datums
- `selfReferenceInjection` -- Sets datum to reference the script's own address

**Advanced Attacks**
- `mutualExclusionAttack` -- Tests ordering and race condition vulnerabilities
- `redeemerAssetSubstitution` -- Substitutes assets referenced in redeemers

### Using Threat Models with TestingInterface

Enable threat models by implementing the `threatModels` field in your
`TestingInterface` instance:

```haskell
instance TestingInterface AuctionState where
  -- ... other fields ...

  threatModels =
    [ unprotectedScriptOutput
    , doubleSatisfaction
    , signatoryRemoval
    , largeValueAttackWith 10
    ]
```

The framework automatically runs each threat model against every transaction
produced by `perform`. Results are tracked per model:

- **Passed**: The attack was correctly rejected by the validator
- **Skipped**: Preconditions not met (e.g., no script inputs to attack)
- **Failed**: Vulnerability found -- the attack succeeded

When a threat model finds a vulnerability, it stops running on subsequent
transactions (early-stop behavior) and reports the counterexample with full
transaction details.

### Expected Vulnerabilities

For testing intentionally vulnerable contracts or documenting known issues, use
`expectedVulnerabilities`:

```haskell
instance TestingInterface VulnerableEscrowState where
  -- ... other fields ...

  expectedVulnerabilities = [timeBoundManipulation]
```

This inverts the pass/fail semantics:

- **Attack succeeds**: Test passes (vulnerability correctly detected)
- **Attack fails**: Test fails (expected vulnerability not found)

Unlike `threatModels`, expected vulnerabilities never early-stop -- they run
against all transactions to ensure the vulnerability is consistently
exploitable. This is useful for CTF-style challenges, regression testing known
issues, or verifying that a vulnerability exists before fixing it.

### Writing Custom Threat Models

Custom threat models use the `ThreatModel` monad with do-notation. The general
pattern is: select elements, set preconditions, apply modifications, assert the
result.

```haskell
import Convex.ThreatModel

-- Attack: try to redirect a continuation output to the attacker
stealContinuation :: ThreatModel ()
stealContinuation = Named "Steal Continuation Output" $ do
  -- Find a script input
  scriptInput <- anyInputSuchThat (not . isKeyAddressAny . addressOf)
  let scriptAddr = addressOf scriptInput

  -- Find continuation outputs (outputs going back to the same script)
  outputs <- getTxOutputs
  let continuations = filter ((== scriptAddr) . addressOf) outputs
  threatPrecondition $ ensure (not $ null continuations)

  -- Pick one to attack
  target <- pickAny continuations

  -- Add context for failure reports
  counterexampleTM $ "Redirecting output from " <> show scriptAddr

  -- Get a signer to use as the attacker
  signer <- anySigner

  -- Assert that redirecting the output should fail validation
  shouldNotValidate $ changeAddressOf target (keyAddressAny signer)
```

Key combinators:

| Category       | Functions                                                                    |
| -------------- | ---------------------------------------------------------------------------- |
| Selection      | `anyInput`, `anyOutput`, `anySigner`, `anyInputSuchThat`, `pickAny`          |
| Preconditions  | `ensure`, `ensureHasInputAt`, `threatPrecondition`, `failPrecondition`       |
| Assertions     | `shouldNotValidate` (attack must fail), `shouldValidate` (must still work)   |
| Reporting      | `counterexampleTM`, `Named`                                                  |
| Modifications  | `changeAddressOf`, `changeValueOf`, `changeDatumOf`, `removeOutput`, `addOutput`, `removeRequiredSigner` |

`TxModifier` is a `Monoid`, so compose multiple modifications with `<>`:

```haskell
shouldNotValidate $
  changeValueOf output reducedValue
    <> removeRequiredSigner signer
```

## Examples

The test suite includes examples covering a range of contract patterns and
vulnerability classes. All examples are in `src/testing-interface/test/`.

### Plinth Examples

| Example                  | Description                                                                                                   | Key Pattern                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| **SampleSpec**           | Minimal lock-and-spend with a validator checking boolean flags.                                               | Basic script interaction                               |
| **PingPongSpec**         | State machine (Pinged/Ponged/Stopped) with full TestingInterface, 4 threat models, secure and vulnerable versions. | State machines, threat model integration               |
| **PingPongCoverageSpec** | Coverage-driven testing targeting edge cases and defensive code paths.                                        | Testing unreachable branches, coverage tracking        |
| **BountySpec**           | Bounty contract with double satisfaction vulnerability. Tests both vulnerable and secure versions.             | Standalone threat model testing with `runThreatModelM` |

### Aiken Examples

Contracts loaded from `test/data/aiken-contracts-example.json`. Source
validators in `aiken-contracts-example/validators/`.

| Example                       | Description                                                                                            | Key Pattern                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| **AikenSpec**                 | Simple "check answer" validator (datum + redeemer == 43).                                              | Basic blueprint loading                                    |
| **AikenPingPongSpec**         | Aiken version of the PingPong state machine.                                                           | Identical testing pattern across languages                 |
| **AikenBankSpec**             | Two-validator bank + account with 4 progressive vulnerability levels.                                  | Multi-validator systems, parameterized scripts             |
| **AikenVestingSpec**          | Time-locked vesting, vulnerable to time bound manipulation.                                            | Time-based vulnerabilities, `expectedVulnerabilities`      |
| **AikenSellNftSpec**          | NFT marketplace where a single payment can satisfy multiple listings.                                  | Double satisfaction, `expectedVulnerabilities`              |
| **AikenMultisigTreasurySpec** | 2-of-2 multisig (v1, v2, v3) vulnerable to signatory removal and output redirection.                   | Authorization vulnerabilities, `expectedVulnerabilities`   |
| **AikenTipJarSpec**           | Tip jar accumulation pattern (v1, v2) with large data/value attacks.                                   | Combined `threatModels` and `expectedVulnerabilities`      |
| **AikenHelloWorldSpec**       | Password-protected lock ("Hello CTF!").                                                                | Simple one-shot spend                                      |
| **AikenKingOfCardanoSpec**    | "King of the hill" vulnerable to self-reference injection.                                             | Self-reference attacks, `expectedVulnerabilities`          |
| **AikenLendingSpec**          | Lending protocol contract.                                                                             | DeFi patterns                                              |
| **AikenPurchaseOfferSpec**    | Purchase offer contract.                                                                               | Offer/acceptance patterns                                  |

## Generic Dependencies

| Name           | Version    |
| -------------- | ---------- |
| GHC            | 9.6.6      |
| Cabal          | 3.10.3.0   |
| cardano-node   | 10.6.1     |
| cardano-api    | 10.17.2.0  |

### sc-tools Dependencies

This project depends on the following packages from
[sc-tools](https://github.com/input-output-hk/sc-tools):

- `convex-base` -- Core functions and types
- `convex-coin-selection` -- Transaction balancing
- `convex-mockchain` -- Test emulator
- `convex-node-client` -- Node client wrappers
- `convex-optics` -- Lenses for cardano-api
- `convex-wallet` -- Wallet implementation

## Contributing

Bug reports and pull requests are welcome. Please open an issue to discuss
proposed changes before submitting large PRs.

- **Issues**: Please report bugs and feature requests in [this repository's issue tracker](https://github.com/input-output-hk/sc-testing-tools/issues)
- **Upstream sc-tools**: [input-output-hk/sc-tools](https://github.com/input-output-hk/sc-tools)

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE)
for details.
