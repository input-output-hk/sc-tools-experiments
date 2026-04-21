# convex-testing-interface

Property-based testing interface for Cardano smart contracts using QuickCheck.

## Overview

This package provides a testing interface for Cardano smart contracts using property-based testing.

## Key Features

- **Testing Interface**: Define your contract's behavior and automatically test that the implementation matches
- **Property-Based Testing**: Uses QuickCheck to generate random action sequences
- **MockChain Integration**: Tests run on `convex-mockchain` for fast, deterministic testing
- **Threat Model Integration**: Automatically run threat models against generated transactions via `ThreatModelsFor`
- **Negative Testing**: Automatically tests that invalid actions are properly rejected
- **Type-Safe**: Leverage Haskell's type system to ensure correct test definitions

## Quick Start

### 1. Define Your Model State

The model state tracks the expected state of your smart contract. It should capture
everything needed to validate that the blockchain matches your expectations.

```haskell
data MyContractState = MyContractState
  { balance :: Integer
  , owner :: Wallet
  } deriving (Eq, Show)
```

### 2. Implement the TestingInterface

The `TestingInterface` typeclass defines your contract's behavior. There is no
separate `nextState` function -- the `perform` method both executes blockchain
operations and returns the updated model state.

```haskell
instance TestingInterface MyContractState where
  data Action MyContractState
    = Deposit Wallet Value
    | Withdraw Wallet Value
    deriving (Show, Eq)

  -- | Initialize the contract on the mockchain and return the initial model state.
  -- This runs in TestingMonadT, so you can submit transactions here.
  initialize = do
    let txBody = execBuildTx $
          payToScriptInlineDatum networkId scriptHash initialDatum NoStakeAddress (lovelaceToValue 0)
    void $ tryBalanceAndSubmit mempty w1 txBody TrailingChange []
    pure $ MyContractState 0 w1

  -- | Generate random actions based on the current model state.
  arbitraryAction s = oneof
    [ Deposit <$> arbitraryWallet <*> genValue
    , Withdraw <$> pure (owner s) <*> genValue
    ]

  -- | Filter out invalid actions before they are attempted.
  precondition s (Withdraw _ v) = balance s >= valueOf v
  precondition _ _ = True

  -- | Execute an action on the blockchain AND return the new model state.
  -- The current model state is provided as the first argument.
  perform s (Deposit wallet val) = do
    let tx = execBuildTx $ payToScriptAddress myScript val
    void $ balanceAndSubmit mempty wallet tx TrailingChange []
    pure $ s { balance = balance s + valueOf val }

  perform s (Withdraw wallet val) = do
    utxos <- findScriptOutputs myScript
    let tx = execBuildTx $ do
          spendScriptOutput (head utxos) myRedeemer
          payToAddress (addressOf wallet) val
    void $ balanceAndSubmit mempty wallet tx TrailingChange []
    pure $ s { balance = balance s - valueOf val }

  -- | Optional: validate that the blockchain state matches the model.
  validate s = do
    actualBalance <- queryScriptBalance myScript
    pure (actualBalance == balance s)
```

Key points:
- `initialize` replaces the old `initialState` pure value. It runs in `TestingMonadT`,
  so you can deploy contracts and submit setup transactions.
- `perform` takes the current state and an action, executes on-chain operations, and
  returns the new state. This replaces the old pattern of having a separate `nextState`
  pure function.
- `validate` is optional (defaults to `True`). It runs after each action to check
  that blockchain state matches the model.

### 3. Implement ThreatModelsFor

The `ThreatModelsFor` typeclass declares which threat models should be run against
transactions generated during property testing. Each threat model is automatically
evaluated against every transaction produced by a successful positive test run.

```haskell
instance ThreatModelsFor MyContractState where
  -- Threat models that SHOULD NOT find vulnerabilities (test passes if they don't).
  -- Default: all parameterless threat models minus expectedVulnerabilities.
  threatModels =
    [ unprotectedScriptOutput
    , largeDataAttackWith 10
    , largeValueAttackWith 10
    ]

  -- Threat models that SHOULD find vulnerabilities (test passes if they do).
  -- Use this for known issues you haven't fixed yet.
  expectedVulnerabilities = []
```

If you don't override `threatModels`, the default runs **all** built-in threat models
(from `allThreatModels`) minus any listed in `expectedVulnerabilities`. The built-in
threat models include:

- `unprotectedScriptOutput` -- outputs can be redirected away from the script
- `doubleSatisfaction` -- a single input satisfies multiple scripts
- `largeDataAttack` / `largeValueAttack` -- bloated datums or values are accepted
- `inputDuplication` -- duplicate inputs are accepted
- `signatoryRemoval` -- required signatories can be removed
- `datumListBloatAttack` / `datumByteBloatAttack` -- datum bloating variants
- `duplicateListEntryAttack` -- duplicate list entries in datums
- `mutualExclusionAttack` -- mutual exclusion violations
- `negativeIntegerAttack` -- negative integers where positives are expected
- `redeemerAssetSubstitution` -- redeemer assets can be substituted
- `selfReferenceInjection` -- self-referencing datum injection
- `timeBoundManipulation` -- time bound manipulation
- `valueUnderpaymentAttack` -- value underpayment

### 4. Write Properties and Run Tests

```haskell
main :: IO ()
main = defaultMain $ testGroup "My Contract"
  [ propRunActions @MyContractState "testing interface"
  ]
```

`propRunActions` requires the `ThreatModelsFor` constraint. It automatically creates
a test group containing:

1. **Positive tests** -- random valid action sequences are executed and validated
2. **Negative tests** -- actions that violate preconditions are checked to fail
3. **Threat model tests** -- one test case per threat model, evaluated against all transactions from positive tests
4. **Expected vulnerability tests** -- threat models expected to find issues (inverted pass/fail)

For custom options (verbosity, max actions, etc.):

```haskell
propRunActionsWithOptions @MyContractState "testing interface" myRunOptions
```

## Architecture

### Core Types

- **`TestingInterface state`**: Typeclass defining your contract's testing model
- **`ThreatModelsFor state`**: Typeclass declaring threat models for your contract
- **`Action state`**: Associated type family for actions on your contract
- **`TestingMonadT m`**: The monad tests run in (wraps `MockchainT` with error handling)

### Test Flow

1. **Initialize**: Run `initialize` to deploy contracts and produce the initial model state
2. **Generate actions**: Use `arbitraryAction` and `precondition` to produce valid action sequences
3. For each action:
   - Execute it on the mockchain and compute the new model state (`perform`)
   - Validate blockchain matches expected behavior (`validate`)
4. **Threat models**: Run each declared threat model against every transaction produced during the test
5. **Negative testing**: Verify that precondition-violating actions are rejected

### TestingMonadT

Tests run in `TestingMonadT`, which wraps `MockchainT` with `ExceptT BalanceTxError`:

```haskell
newtype TestingMonadT m a = TestingMonadT
  { unTestingMonadT :: ExceptT (BalanceTxError ConwayEra) (MockchainT ConwayEra m) a
  }
```

This gives you access to:
- All `MonadBlockchain` operations (send transactions, query UTxOs, etc.)
- All `MonadMockchain` operations (get/set UTxO state, advance slots, etc.)
- Proper error handling for transaction balancing failures

## Dependencies

This package requires:
- `QuickCheck` >= 2.14
- `convex-mockchain`
- `convex-base`
- `cardano-api`

### Build Environment

The package requires:
- GHC 9.6.6
- Cabal 3.10.3.0
- Access to cardano-haskell-packages (CHaP)

For development, you can use Nix:
```bash
nix develop
cabal build convex-testing-interface
```

## Contributing

This is part of the sc-tools project. Contributions welcome!

## License

Apache 2.0
