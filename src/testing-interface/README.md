# convex-testing-interface

Property-based testing interface for Cardano smart contracts using QuickCheck.

## Overview

This package provides a testing interface for Cardano smart contracts using property-based testing.

## Key Features

- **Testing Interface**: Define your contract's behavior and automatically test that the implementation matches
- **Property-Based Testing**: Uses QuickCheck to generate random action sequences
- **MockChain Integration**: Tests run on `convex-mockchain` for fast, deterministic testing
- **Type-Safe**: Leverage Haskell's type system to ensure correct test definitions

## Quick Start

### 1. Define Your Model State

```haskell
data MyContractState = MyContractState
  { balance :: Integer
  , owner :: Wallet
  } deriving (Eq, Show)
```

### 2. Define Actions

```haskell
instance TestingInterface MyContractState where
  data Action MyContractState
    = Deposit Wallet Value
    | Withdraw Wallet Value
    deriving (Show, Eq)
```

### 3. Implement the TestingInterface Class

```haskell
  initialState = MyContractState 0 w1

  arbitraryAction s = oneof
    [ Deposit <$> arbitraryWallet <*> genValue
    , Withdraw <$> pure (owner s) <*> genValue
    ]

  precondition s (Withdraw _ v) = balance s >= valueOf v
  precondition _ _ = True

  nextState s (Deposit _ v) = s { balance = balance s + valueOf v }
  nextState s (Withdraw _ v) = s { balance = balance s - valueOf v }

  perform (Deposit wallet val) = do
    let tx = execBuildTx' $ payToScriptAddress myScript val
    CoinSelection.balanceAndSubmit wallet tx

  perform (Withdraw wallet val) = do
    utxos <- findScriptOutputs myScript
    let tx = execBuildTx' $ do
          spendScriptOutput (head utxos) myRedeemer
          payToAddress (Wallet.addressOf wallet) val
    CoinSelection.balanceAndSubmit wallet tx
```

### 4. Write Properties

```haskell
prop_testingInterface :: Actions MyContractState -> Property
prop_testingInterface = propRunActions
```

### 5. Run Tests

```haskell
main :: IO ()
main = defaultMain $ testGroup "My Contract"
  [ testProperty "testing interface" prop_testingInterface
  ]
```

## Architecture

### Core Types

- **`TestingInterface state`**: Typeclass defining your contract's testing interface
- **`Action state`**: Type family for actions on your contract
- **`Actions state`**: Sequence of actions to test
- **`MockChainT`**: Monad for running tests on the mockchain

### Test Flow

1. Generate random sequence of valid actions using `arbitraryAction` and `precondition`
2. For each action:
   - Execute it on the real blockchain (`perform`)
   - Update the testing interface state (`nextState`)
   - Validate blockchain matches expected behavior (`validate`)
3. Check that no errors occurred and all validations passed

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
