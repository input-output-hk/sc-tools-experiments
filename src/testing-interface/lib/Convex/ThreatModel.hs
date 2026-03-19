{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unused-matches -Wno-name-shadowing #-}

{- | The threat modelling framework allows you to write down and test properties of modifications of
  valid transactions.

  A threat model is represented by a value in the `ThreatModel` monad, and is evaluated in the
  context of a single valid transaction and the chain state at the point it validated (a
  `ThreatModelEnv`). Transactions and chain states can most easily be obtained using a
  `ContractModelResult` from `runContractModel`, but they can in principle come from anywhere.

  As an example, here is a `ThreatModel` that checks that any interaction with @myScript@
  requires @theToken@ to be present:

@
    tokenThreatModel :: 'ThreatModel' ()
    tokenThreatModel = do
      'ensureHasInputAt' myScript

      let hasToken out = theToken ``leqValue`` 'valueOf' out
      i <- 'anyInputSuchThat'  hasToken
      o <- 'anyOutputSuchThat' hasToken

      'shouldNotValidate' $ 'changeValueOf' i ('valueOf' i <> negateValue theToken)
                       <> 'changeValueOf' o ('valueOf' o <> negateValue theToken)
@

  For a more complex example see "Test.QuickCheck.ThreatModel.DoubleSatisfaction".
-}
module Convex.ThreatModel (
  -- * Transaction modifiers

  -- ** Types
  TxModifier,
  Input (..),
  Output (..),
  Datum,
  Redeemer,

  -- ** Modifiers
  IsInputOrOutput (..),
  addOutput,
  removeOutput,
  addKeyInput,
  addPlutusScriptInput,
  addPlutusScriptInputV3,
  addSimpleScriptInput,
  addReferenceScriptInput,
  addKeyReferenceInput,
  addPlutusScriptReferenceInput,
  addSimpleScriptReferenceInput,
  removeInput,
  changeRedeemerOf,
  changeValidityRange,
  changeValidityLowerBound,
  changeValidityUpperBound,
  replaceTx,

  -- * Threat models
  ThreatModel (Named),
  ThreatModelEnv (..),
  ThreatModelOutcome (..),
  threatModelEnvs,
  runThreatModel,
  runThreatModelM,
  runThreatModelMQuiet,
  runThreatModelCheck,
  assertThreatModel,
  getThreatModelName,

  -- ** Preconditions
  threatPrecondition,
  inPrecondition,
  ensure,
  ensureHasInputAt,
  failPrecondition,

  -- ** Validation
  shouldValidate,
  shouldNotValidate,
  ValidityReport (..),
  validate,

  -- ** Querying the environment
  getThreatModelEnv,
  originalTx,
  getTxInputs,
  getTxReferenceInputs,
  getTxOutputs,
  getRedeemer,
  getTxRequiredSigners,

  -- ** Random generation
  forAllTM,
  pickAny,
  anySigner,
  anyInput,
  anyReferenceInput,
  anyOutput,
  anyInputSuchThat,
  anyReferenceInputSuchThat,
  anyOutputSuchThat,

  -- ** Monitoring
  counterexampleTM,
  tabulateTM,
  collectTM,
  classifyTM,
  monitorThreatModel,
  monitorLocalThreatModel,

  -- * Wallet selection
  SigningWallet (..),

  -- * Cardano API helpers
  -- $cardanoHelpers
  projectAda,
  leqValue,

  -- ** Addresses
  keyAddressAny,
  scriptAddressAny,
  isKeyAddressAny,

  -- ** Datums
  txOutDatum,
  toScriptData,
  datumOfTxOut,

  -- * Pretty printing
  -- $prettyPrinting
  paragraph,
  prettyAddress,
  prettyValue,
  prettyDatum,
  prettyInput,
  prettyOutput,
  module X,
) where

import Cardano.Api as X

import Control.Lens ((%~), (&), (^.))
import Control.Monad
import Data.Map qualified as Map
import Text.PrettyPrint hiding ((<>))
import Text.Printf

import Test.QuickCheck
import Test.QuickCheck qualified as QC

import Convex.Class (MockChainState, MonadMockchain (..), coverageData, getUtxo, setTimeToValidRange)
import Convex.MockChain (applyTransaction, runMockchain)
import Convex.NodeParams (NodeParams, ledgerProtocolParameters)
import Convex.ThreatModel.Cardano.Api
import Convex.ThreatModel.Cardano.Api qualified as TM (detectSigningWallet, rebalanceAndSign, txRequiredSigners)
import Convex.ThreatModel.Pretty
import Convex.ThreatModel.TxModifier
import Convex.Wallet (Wallet)

{- $cardanoHelpers
Some convenience functions making it easier to work with Cardano API.
-}

{- $prettyPrinting
The framework already prints the original transaction and the results of validating modified
transactions in counterexamples. To include more information you can use `counterexampleTM` with
the functions below.
-}

{- | The context in which a `ThreatModel` is executed. Contains a transaction, its UTxO set and the
  protocol parameters. See `getThreatModelEnv` and `originalTx` to access this information in a
  threat model.
-}
data ThreatModelEnv = ThreatModelEnv
  { currentTx :: Tx Era
  , currentUTxOs :: UTxO Era
  , pparams :: LedgerProtocolParameters Era
  }

-- | How to determine the wallet for re-balancing and re-signing modified transactions.
data SigningWallet
  = -- | Detect the signing wallet automatically from the transaction's witnesses.
    AutoSign
  | -- | Use the specified wallet for signing.
    SignWith Wallet

-- | Create `ThreatModelEnv`s by reapplying the given transactions in order, starting with the given chain state.
threatModelEnvs :: NodeParams Era -> [Tx Era] -> MockChainState Era -> [ThreatModelEnv]
threatModelEnvs params txs chainState0 = fst $ foldM go chainState0 txs
 where
  go chainState tx =
    let txBodyContent = getTxBodyContent $ getTxBody tx
        rng = (txValidityLowerBound txBodyContent, txValidityUpperBound txBodyContent)
        (utxo, chainState') = runMockchain (setTimeToValidRange rng >> getUtxo) params chainState
        res = applyTransaction params chainState' tx
        threatModelEnv =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = fromLedgerUTxO shelleyBasedEra utxo
            , pparams = params ^. ledgerProtocolParameters
            }
     in case res of
          Left e -> error $ "Unexpected error after replaying transactions: " ++ show e
          Right (chainState'', _) -> ([threatModelEnv], chainState'')

-- | Structured outcome of running a threat model against a transaction.
data ThreatModelOutcome
  = -- | At least one transaction was tested, all checks passed
    TMPassed
  | -- | A check failed, with error details
    TMFailed String
  | -- | Preconditions were never met (all transactions skipped)
    TMSkipped
  | -- | Threat model crashed with an exception
    TMError String
  deriving (Eq, Show)

{- | The threat model monad is how you construct threat models. It works in the context of a given
  transaction and the UTxO set at the point where the transaction was validated (see
  `ThreatModelEnv`) and lets you construct properties about the validatity of modifications of
  the original transaction.
-}
data ThreatModel a where
  Validate
    :: TxModifier
    -> (ValidityReport -> ThreatModel a)
    -> ThreatModel a
  Generate
    :: (Show a)
    => Gen a
    -> (a -> [a])
    -> (a -> ThreatModel b)
    -> ThreatModel b
  GetCtx :: (ThreatModelEnv -> ThreatModel a) -> ThreatModel a
  Skip :: ThreatModel a
  InPrecondition
    :: (Bool -> ThreatModel a)
    -> ThreatModel a
  Fail
    :: String
    -> ThreatModel a
  Monitor
    :: (Property -> Property)
    -> ThreatModel a
    -> ThreatModel a
  MonitorLocal
    :: (Property -> Property)
    -> ThreatModel a
    -> ThreatModel a
  Done
    :: a
    -> ThreatModel a
  Named
    :: String
    -- ^ Threat model name
    -> ThreatModel a
    -- ^ The wrapped threat model
    -> ThreatModel a

instance Functor ThreatModel where
  fmap = liftM

instance Applicative ThreatModel where
  pure = Done
  (<*>) = ap

instance Monad ThreatModel where
  Validate tx cont >>= k = Validate tx (cont >=> k)
  Skip >>= _ = Skip
  InPrecondition cont >>= k = InPrecondition (cont >=> k)
  Fail err >>= _ = Fail err
  Generate gen shr cont >>= k = Generate gen shr (cont >=> k)
  GetCtx cont >>= k = GetCtx (cont >=> k)
  Monitor m cont >>= k = Monitor m (cont >>= k)
  MonitorLocal m cont >>= k = MonitorLocal m (cont >>= k)
  Done a >>= k = k a
  Named n m >>= k = Named n (m >>= k)

instance MonadFail ThreatModel where
  fail = Fail

-- \| Evaluate a `ThreatModel` on a list of transactions with their context. Fails the property if
--   the threat model fails on any of the transactions.
runThreatModel :: ThreatModel a -> [ThreatModelEnv] -> Property
runThreatModel = go False
 where
  go b model [] = b ==> property True
  go b model (env : envs) = interp (counterexample $ show info) model
   where
    info =
      vcat
        [ ""
        , block
            "Original UTxO set"
            [ prettyUTxO $
                restrictUTxO (currentTx env) $
                  currentUTxOs env
            ]
        , ""
        , block "Original transaction" [prettyTx $ currentTx env]
        , ""
        ]
    interp mon = \case
      Validate mods k ->
        interp mon $
          k $
            let (modifiedTx, modifiedUtxo) = applyTxModifier (currentTx env) (currentUTxOs env) mods
             in validateTx (pparams env) modifiedTx modifiedUtxo
      Generate gen shr k ->
        forAllShrinkBlind gen shr $
          interp mon . k
      GetCtx k ->
        interp mon $
          k env
      Skip -> go b model envs
      InPrecondition k -> interp mon (k False)
      Fail err -> mon $ counterexample err False
      Monitor m k -> m $ interp mon k
      MonitorLocal m k -> interp (mon . m) k
      Done{} -> go True model envs
      Named _n k -> interp mon k

-- | Evaluate a `ThreatModel` on a list of transactions.
assertThreatModel
  :: ThreatModel a
  -> LedgerProtocolParameters Era
  -> [(Tx Era, UTxO Era)]
  -> Property
assertThreatModel m pparams' txs = runThreatModel m envs
 where
  envs =
    [ ThreatModelEnv tx utxo pparams'
    | (tx, utxo) <- txs
    ]

{- | Run threat model inside MockchainT with full Phase 1 + Phase 2 validation.

Unlike 'runThreatModel' which only validates Phase 2 (script execution),
this version uses re-balancing and re-signing for modified transactions,
then performs full Phase 1 + Phase 2 validation via 'applyTransaction'.

This catches vulnerabilities that would be masked by signature/fee failures
in the simpler Phase 2-only validation.

The wallet parameter controls signing:
- @SignWith wallet@ - use the specified wallet for signing
- @AutoSign@ - detect the signing wallet from the transaction's witnesses

Usage:
@
result <- runMockchain0IOWith utxos params $ do
  -- ... run your actions to get a transaction ...
  runThreatModelM (SignWith Wallet.w1) unprotectedScriptOutput [env]
  -- or auto-detect:
  runThreatModelM AutoSign unprotectedScriptOutput [env]
@
-}
runThreatModelM
  :: (MonadMockchain Era m, MonadFail m, MonadIO m)
  => SigningWallet
  -> ThreatModel a
  -> [ThreatModelEnv]
  -> m Property
runThreatModelM = runThreatModelM' False

{- | Like 'runThreatModelM' but suppresses verbose counterexample annotations.

This is useful for 'expectFailure' tests where you want the test to fail
(proving vulnerability exists) but don't want the lengthy counterexample
output cluttering test results.

The property still succeeds/fails correctly based on shouldValidate/shouldNotValidate
checks, but Monitor/MonitorLocal annotations (counterexampleTM, etc.) are ignored.

The wallet parameter controls signing (see 'runThreatModelM' for details).
-}
runThreatModelMQuiet
  :: (MonadMockchain Era m, MonadFail m, MonadIO m)
  => SigningWallet
  -> ThreatModel a
  -> [ThreatModelEnv]
  -> m Property
runThreatModelMQuiet = runThreatModelM' True

-- | Internal shared implementation for 'runThreatModelM' and 'runThreatModelMQuiet'.
runThreatModelM'
  :: (MonadMockchain Era m, MonadFail m, MonadIO m)
  => Bool
  -- ^ quiet: suppress counterexample annotations
  -> SigningWallet
  -> ThreatModel a
  -> [ThreatModelEnv]
  -> m Property
runThreatModelM' quiet signingWallet = go False
 where
  go b _model [] = pure $ b ==> property True
  go b model (env : envs) = do
    -- Resolve wallet: use provided or detect from transaction
    let resolvedWallet = case signingWallet of
          SignWith w -> Right w
          AutoSign -> TM.detectSigningWallet (currentTx env)
    case resolvedWallet of
      Left err -> pure $ counterexample err False
      Right wallet -> interpM initialMon wallet model
   where
    initialMon = if quiet then id else counterexample (show info)

    info =
      vcat
        [ ""
        , block
            "Original UTxO set"
            [ prettyUTxO $
                restrictUTxO (currentTx env) $
                  currentUTxOs env
            ]
        , ""
        , block "Original transaction" [prettyTx $ currentTx env]
        , ""
        ]

    interpM mon wallet = \case
      Validate mods k -> do
        let (modifiedTx, modifiedUtxo) = applyTxModifier (currentTx env) (currentUTxOs env) mods
        -- Re-balance and re-sign the modified transaction
        params <- askNodeParams
        rebalancedTx <- rebalanceAndSignM wallet modifiedTx modifiedUtxo
        -- Validate with full Phase 1 + Phase 2
        (report, covData) <- validateTxM params rebalancedTx modifiedUtxo
        -- Accumulate coverage into the running MockChainState
        modifyMockChainState $ \s -> ((), s & coverageData %~ (<> covData))
        interpM mon wallet (k report)
      Generate gen _shr k -> do
        -- Use QuickCheck's generate in IO
        a <- liftIO $ QC.generate gen
        interpM mon wallet (k a)
      GetCtx k ->
        interpM mon wallet (k env)
      Skip -> go b model envs
      InPrecondition k -> interpM mon wallet (k False)
      Fail err -> pure $ if quiet then property False else mon $ counterexample err False
      Monitor m k -> if quiet then interpM mon wallet k else m <$> interpM mon wallet k
      MonitorLocal m k -> if quiet then interpM mon wallet k else interpM (mon . m) wallet k
      Done{} -> go True model envs
      Named _n k -> interpM mon wallet k

-- | Extract the name from a threat model, if it was defined with 'Named'.
getThreatModelName :: ThreatModel a -> Maybe String
getThreatModelName (Named n _) = Just n
getThreatModelName _ = Nothing

{- | Run a threat model and return a structured outcome instead of a Property.
  Coverage is still accumulated in MockChainState as a side effect.

  Rebalancing failures (e.g., "No change output found") are treated as skipped
  because they indicate the transaction modification cannot be applied to this
  particular transaction, similar to a precondition failure.

  The wallet parameter controls signing:
  - @SignWith wallet@ - use the specified wallet for signing
  - @AutoSign@ - detect the signing wallet from the transaction's witnesses
-}
runThreatModelCheck
  :: (MonadMockchain Era m, MonadFail m, MonadIO m)
  => SigningWallet
  -> ThreatModel a
  -> [ThreatModelEnv]
  -> m ThreatModelOutcome
runThreatModelCheck signingWallet = go False
 where
  go b _model [] = pure $ if b then TMPassed else TMSkipped
  go b model (env : envs) = do
    -- Resolve wallet: use provided or detect from transaction
    let resolvedWallet = case signingWallet of
          SignWith w -> Right w
          AutoSign -> TM.detectSigningWallet (currentTx env)
    case resolvedWallet of
      Left err -> pure (TMError err) -- Continue to next env would lose the error, so return it
      Right wallet -> checkInterp wallet model
   where
    checkInterp wallet = \case
      Validate mods k -> do
        let (modifiedTx, modifiedUtxo) = applyTxModifier (currentTx env) (currentUTxOs env) mods
        params <- askNodeParams
        -- Try rebalancing - failure means this modification can't be tested on this tx
        rebalanceResult <- TM.rebalanceAndSign wallet modifiedTx modifiedUtxo
        case rebalanceResult of
          Left _err ->
            go b model envs -- Rebalancing failed, skip to next tx (like precondition failure)
          Right rebalancedTx -> do
            (report, covData) <- validateTxM params rebalancedTx modifiedUtxo
            modifyMockChainState $ \s -> ((), s & coverageData %~ (<> covData))
            checkInterp wallet (k report)
      Generate gen _shr k -> do
        a <- liftIO $ QC.generate gen
        checkInterp wallet (k a)
      GetCtx k ->
        checkInterp wallet (k env)
      Skip -> go b model envs
      InPrecondition k -> checkInterp wallet (k False)
      Fail err -> pure (TMFailed err)
      Monitor _m k -> checkInterp wallet k -- No Property to wrap; drop monitoring
      MonitorLocal _m k -> checkInterp wallet k -- No Property to wrap; drop monitoring
      Done{} -> go True model envs
      Named _n k -> checkInterp wallet k

{- | Check a precondition. If the argument threat model fails, the evaluation of the current
  transaction is skipped. If all transactions in an evaluation of `runThreatModel` are skipped
  it is considered a /discarded/ test for QuickCheck.

  Having the argument to `threatPrecondition` be a threat model computation instead of a plain
  boolean allows you do express preconditions talking about the validation of modified
  transactions (using `shouldValidate` and `shouldNotValidate`). See `ensure` for the boolean
  version.
-}
threatPrecondition :: ThreatModel a -> ThreatModel a
threatPrecondition = \case
  Skip -> Skip
  InPrecondition k -> k True
  Fail reason -> Monitor (tabulate "Precondition failed with reason" [reason]) Skip
  Validate tx k -> Validate tx (threatPrecondition . k)
  Generate g s k -> Generate g s (threatPrecondition . k)
  GetCtx k -> GetCtx (threatPrecondition . k)
  Monitor m k -> Monitor m (threatPrecondition k)
  MonitorLocal m k -> MonitorLocal m (threatPrecondition k)
  Done a -> Done a
  Named n k -> Named n (threatPrecondition k)

failPrecondition :: String -> ThreatModel a
failPrecondition reason = Monitor (tabulate "Precondition failed with reason" [reason]) Skip

-- | Same as `threatPrecondition` but takes a boolean and skips the test if the argument is @False@.
ensure :: Bool -> ThreatModel ()
ensure False = Skip
ensure True = pure ()

{- | Precondition that check that the original transaction has an input at a given address. Useful,
  for example, to ensure that you only consider transactions that trie to spend a script output
  from the script under test.
-}
ensureHasInputAt :: AddressAny -> ThreatModel ()
ensureHasInputAt addr = do
  inputs <- getTxInputs
  ensure $ any ((addr ==) . addressOf) inputs

-- | Returns @True@ if evaluated under a `threatPrecondition` and @False@ otherwise.
inPrecondition :: ThreatModel Bool
inPrecondition = InPrecondition Done

{- | The most low-level way to validate a modified transaction. In most cases `shouldValidate` and
  `shouldNotValidate` are preferred.
-}
validate :: TxModifier -> ThreatModel ValidityReport
validate tx = Validate tx pure

{- | Check that a given modification of the original transaction validates. The modified transaction
  is printed in counterexample when this fails, or if it succeeds in a precondition and the test
  fails later.
-}
shouldValidate :: TxModifier -> ThreatModel ()
shouldValidate = shouldValidateOrNot True

{- | Check that a given modification of the original transaction does not validate. The modified
  transaction is printed in counterexample when it does validate, or if it doesn't in a satisfied
  precondition and the test fails later.
-}
shouldNotValidate :: TxModifier -> ThreatModel ()
shouldNotValidate = shouldValidateOrNot False

shouldValidateOrNot :: Bool -> TxModifier -> ThreatModel ()
shouldValidateOrNot should txMod = do
  validReport <- validate txMod
  ThreatModelEnv tx utxos _ <- getThreatModelEnv
  let newTx = fst $ applyTxModifier tx utxos txMod
      info str =
        block
          (text str)
          [ block
              "Modifications to original transaction"
              [prettyTxModifier txMod]
          , block
              "Resulting transaction"
              [prettyTx newTx]
          , text ""
          ]
      n't
        | should = "n't"
        | otherwise = "" :: String
      notN't
        | should = "" :: String
        | otherwise = "n't"
  when (should /= valid validReport) $ do
    fail $ show $ info $ printf "Test failure: the following transaction did%s validate" n't
  pre <- inPrecondition
  when pre $
    counterexampleTM $
      show $
        info $
          printf "Satisfied precondition: the following transaction did%s validate" notN't

-- | Get the current context.
getThreatModelEnv :: ThreatModel ThreatModelEnv
getThreatModelEnv = GetCtx pure

-- | Get the original transaction from the context.
originalTx :: ThreatModel (Tx Era)
originalTx = currentTx <$> getThreatModelEnv

-- | Get the outputs from the original transaction.
getTxOutputs :: ThreatModel [Output]
getTxOutputs = zipWith (flip Output . TxIx) [0 ..] . txOutputs <$> originalTx

-- | Get the inputs from the original transaction.
getTxInputs :: ThreatModel [Input]
getTxInputs = do
  ThreatModelEnv tx (UTxO utxos) _ <- getThreatModelEnv
  pure
    [ Input txout i
    | i <- txInputs tx
    , Just txout <- [Map.lookup i utxos]
    ]

-- | Get the reference inputs from the original transaction.
getTxReferenceInputs :: ThreatModel [Input]
getTxReferenceInputs = do
  ThreatModelEnv tx (UTxO utxos) _ <- getThreatModelEnv
  pure
    [ Input txout i
    | i <- txReferenceInputs tx
    , Just txout <- [Map.lookup i utxos]
    ]

-- | Get the redeemer (if any) for an input of the original transaction.
getRedeemer :: Input -> ThreatModel (Maybe Redeemer)
getRedeemer (Input _ txIn) = do
  tx <- originalTx
  pure $ redeemerOfTxIn tx txIn

-- | Get the required signers from the original transaction body.
getTxRequiredSigners :: ThreatModel [Hash PaymentKey]
getTxRequiredSigners = TM.txRequiredSigners <$> originalTx

-- | Generate a random value. Takes a QuickCheck generator and a `shrink` function.
forAllTM :: (Show a) => Gen a -> (a -> [a]) -> ThreatModel a
forAllTM g s = Generate g s pure

-- | Pick a random input
anyInput :: ThreatModel Input
anyInput = anyInputSuchThat (const True)

-- | Pick a random reference input
anyReferenceInput :: ThreatModel Input
anyReferenceInput = anyReferenceInputSuchThat (const True)

-- | Pick a random output
anyOutput :: ThreatModel Output
anyOutput = anyOutputSuchThat (const True)

-- | Pick a random input satisfying the given predicate.
anyInputSuchThat :: (Input -> Bool) -> ThreatModel Input
anyInputSuchThat p = pickAny . filter p =<< getTxInputs

-- | Pick a random reference input satisfying the given predicate.
anyReferenceInputSuchThat :: (Input -> Bool) -> ThreatModel Input
anyReferenceInputSuchThat p = pickAny . filter p =<< getTxReferenceInputs

-- | Pick a random output satisfying the given predicate.
anyOutputSuchThat :: (Output -> Bool) -> ThreatModel Output
anyOutputSuchThat p = pickAny . filter p =<< getTxOutputs

-- | Pick a random value from a list. Skips the test if the list is empty.
pickAny :: (Show a) => [a] -> ThreatModel a
pickAny xs = do
  ensure (not $ null xs)
  let xs' = zip xs [0 ..]
  fst <$> forAllTM (elements xs') (\(_, i) -> take i xs')

-- | Pick a random signer of the original transaction.
anySigner :: ThreatModel (Hash PaymentKey)
anySigner = pickAny . txSigners =<< originalTx

{- | Monitoring that's shared between all transactions evaulated. Avoid this in favour of
  `tabulateTM`, `collectTM` and `classifyTM` when possible.
-}
monitorThreatModel :: (Property -> Property) -> ThreatModel ()
monitorThreatModel m = Monitor m (pure ())

-- | Monitoring that's local to the current transaction. Use `counterexampleTM` when possible.
monitorLocalThreatModel :: (Property -> Property) -> ThreatModel ()
monitorLocalThreatModel m = MonitorLocal m (pure ())

{- | Print the given string in case this threat model fails. Threat model counterpart of
  the QuickCheck `Test.QuickCheck.counterexample` function.
-}
counterexampleTM :: String -> ThreatModel ()
counterexampleTM = monitorLocalThreatModel . counterexample

-- | Threat model counterpart of QuickCheck's `Test.QuickCheck.tabulate` function.
tabulateTM :: String -> [String] -> ThreatModel ()
tabulateTM = (monitorThreatModel .) . tabulate

-- | Threat model counterpart of QuickCheck's `Test.QuickCheck.collect` function.
collectTM :: (Show a) => a -> ThreatModel ()
collectTM = monitorThreatModel . collect

-- | Threat model counterpart of QuickCheck's `Test.QuickCheck.classify` function.
classifyTM :: Bool -> String -> ThreatModel ()
classifyTM = (monitorThreatModel .) . classify
