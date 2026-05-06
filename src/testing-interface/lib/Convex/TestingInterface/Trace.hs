{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

module Convex.TestingInterface.Trace (
  -- * Test run trace
  TestRunTrace (..),
  TestCategory (..),

  -- * Iteration trace
  IterationTrace (..),
  IterationStatus (..),

  -- * State transitions
  Transition (..),
  TransitionResult (..),

  -- * Transaction summary
  TxSummary (..),
  TxInputSummary (..),
  TxOutputSummary (..),

  -- * Threat model trace
  ThreatModelTrace (..),
  ThreatModelTraceOutcome (..),
) where

import Data.Aeson (ToJSON (..), Value, object, (.=))
import Data.Text (Text)
import GHC.Generics (Generic)

{- | Complete trace of a test run (one QuickCheck property execution = N iterations).
Links to the Tasty test tree via 'trtTestId'.
-}
data TestRunTrace = TestRunTrace
  { trtTestId :: !Int
  -- ^ Tasty test ID (links to the @test_done@ event in the NDJSON stream)
  , trtTestName :: !Text
  -- ^ e.g. "Positive tests"
  , trtPath :: ![Text]
  -- ^ Tasty test path, e.g. @["MyContract", "Positive tests"]@
  , trtCategory :: !TestCategory
  , trtIterations :: ![IterationTrace]
  }
  deriving (Eq, Show, Generic)

-- | Whether this test run is a positive or negative test property.
data TestCategory
  = Positive
  | Negative
  deriving (Eq, Show, Generic)

instance ToJSON TestCategory where
  toJSON Positive = "positive"
  toJSON Negative = "negative"

-- | Trace of a single QuickCheck iteration within a test run.
data IterationTrace = IterationTrace
  { itIndex :: !Int
  -- ^ 0-based iteration number
  , itSeed :: !Int
  -- ^ QuickCheck seed for reproducibility
  , itStatus :: !IterationStatus
  , itTransitions :: ![Transition]
  -- ^ Ordered sequence of actions performed
  , itThreatModels :: ![ThreatModelTrace]
  {- ^ Threat model results applied to this iteration's transactions.
  Only populated for positive tests.
  -}
  }
  deriving (Eq, Show, Generic)

-- | Outcome of a single iteration.
data IterationStatus
  = IterationSuccess
  | IterationFailure !Text
  | IterationDiscarded !Text
  deriving (Eq, Show, Generic)

{- | One step in an iteration: an action was performed, the model state changed,
and a transaction was (possibly) submitted.
-}
data Transition = Transition
  { trStepIndex :: !Int
  -- ^ 0-based index within the iteration
  , trAction :: !Text
  -- ^ @show@ of the @Action state@ value
  , trStateBefore :: !Value
  -- ^ @toJSON@ of the model state before @perform@
  , trStateAfter :: !Value
  -- ^ @toJSON@ of the model state after @perform@
  , trTransaction :: !(Maybe TxSummary)
  {- ^ The transaction produced, if any. @Nothing@ if @perform@ failed
  before building a transaction.
  -}
  , trResult :: !TransitionResult
  }
  deriving (Eq, Show, Generic)

-- | Whether the transaction was successfully submitted to the mockchain.
data TransitionResult
  = -- | TxId as text
    TransitionSuccess !Text
  | -- | Error description
    TransitionFailure !Text
  deriving (Eq, Show, Generic)

{- | Compact representation of a transaction for visualization.
Values are rendered as text to avoid coupling to cardano-api serialization.
-}
data TxSummary = TxSummary
  { txsId :: !(Maybe Text)
  -- ^ TxId if submitted successfully, @Nothing@ otherwise
  , txsInputs :: ![TxInputSummary]
  , txsOutputs :: ![TxOutputSummary]
  , txsMint :: !(Maybe Text)
  -- ^ Rendered mint value, @Nothing@ if no minting
  , txsFee :: !Integer
  -- ^ Fee in lovelace
  , txsSigners :: ![Text]
  -- ^ Required signer key hashes
  , txsValidRange :: !(Maybe Text)
  -- ^ Rendered validity interval
  }
  deriving (Eq, Show, Generic)

-- | Summary of a transaction input.
data TxInputSummary = TxInputSummary
  { tisUtxo :: !Text
  -- ^ @"txid#index"@
  , tisAddress :: !Text
  -- ^ Bech32 or hex address
  , tisValue :: !Text
  -- ^ Rendered value (ada + tokens)
  }
  deriving (Eq, Show, Generic)

-- | Summary of a transaction output.
data TxOutputSummary = TxOutputSummary
  { tosUtxo :: !Text
  -- ^ @"txid#index"@ – the UTxO reference for this output
  , tosAddress :: !Text
  , tosValue :: !Text
  , tosDatum :: !(Maybe Text)
  -- ^ @"inline:\<hash\>"@, @"hash:\<hash\>"@, or @Nothing@
  }
  deriving (Eq, Show, Generic)

{- | What happened when a threat model was applied to a specific transaction
in this iteration.
-}
data ThreatModelTrace = ThreatModelTrace
  { tmtName :: !Text
  -- ^ Name of the threat model (e.g. "unprotectedScriptOutput")
  , tmtTargetTxIndex :: !Int
  -- ^ Index into 'itTransitions' identifying which transaction was targeted
  , tmtModifications :: ![Text]
  -- ^ Human-readable descriptions of each modification applied
  , tmtOriginalTx :: !TxSummary
  -- ^ The original transaction before modification
  , tmtModifiedTx :: !(Maybe TxSummary)
  -- ^ The modified transaction, @Nothing@ if the modification couldn't produce a valid tx body
  , tmtOutcome :: !ThreatModelTraceOutcome
  }
  deriving (Eq, Show, Generic)

-- | Outcome of applying a threat model to a transaction.
data ThreatModelTraceOutcome
  = -- | Modified tx was correctly rejected by the ledger (good!)
    TMTOPassed
  | -- | Modified tx was ACCEPTED by the ledger (vulnerability found!)
    TMTOFailed !Text
  | -- | Couldn't test: rebalancing failed or precondition not met
    TMTOSkipped !Text
  | -- | Unexpected error during threat model execution
    TMTOError !Text
  deriving (Eq, Show, Generic)

-- ---------------------------------------------------------------------
-- ToJSON instances
-- ---------------------------------------------------------------------

instance ToJSON TestRunTrace where
  toJSON t =
    object
      [ "testId" .= trtTestId t
      , "testName" .= trtTestName t
      , "path" .= trtPath t
      , "category" .= trtCategory t
      , "iterations" .= trtIterations t
      ]

instance ToJSON IterationTrace where
  toJSON t =
    object
      [ "index" .= itIndex t
      , "seed" .= itSeed t
      , "status" .= itStatus t
      , "transitions" .= itTransitions t
      , "threatModels" .= itThreatModels t
      ]

instance ToJSON IterationStatus where
  toJSON IterationSuccess =
    object ["status" .= ("success" :: Text)]
  toJSON (IterationFailure msg) =
    object ["status" .= ("failure" :: Text), "message" .= msg]
  toJSON (IterationDiscarded msg) =
    object ["status" .= ("discarded" :: Text), "message" .= msg]

instance ToJSON Transition where
  toJSON t =
    object
      [ "stepIndex" .= trStepIndex t
      , "action" .= trAction t
      , "stateBefore" .= trStateBefore t
      , "stateAfter" .= trStateAfter t
      , "transaction" .= trTransaction t
      , "result" .= trResult t
      ]

instance ToJSON TransitionResult where
  toJSON (TransitionSuccess txId) =
    object ["status" .= ("success" :: Text), "txId" .= txId]
  toJSON (TransitionFailure err) =
    object ["status" .= ("failure" :: Text), "error" .= err]

instance ToJSON TxSummary where
  toJSON t =
    object
      [ "id" .= txsId t
      , "inputs" .= txsInputs t
      , "outputs" .= txsOutputs t
      , "mint" .= txsMint t
      , "fee" .= txsFee t
      , "signers" .= txsSigners t
      , "validRange" .= txsValidRange t
      ]

instance ToJSON TxInputSummary where
  toJSON t =
    object
      [ "utxo" .= tisUtxo t
      , "address" .= tisAddress t
      , "value" .= tisValue t
      ]

instance ToJSON TxOutputSummary where
  toJSON t =
    object
      [ "utxo" .= tosUtxo t
      , "address" .= tosAddress t
      , "value" .= tosValue t
      , "datum" .= tosDatum t
      ]

instance ToJSON ThreatModelTrace where
  toJSON t =
    object
      [ "name" .= tmtName t
      , "targetTxIndex" .= tmtTargetTxIndex t
      , "modifications" .= tmtModifications t
      , "originalTx" .= tmtOriginalTx t
      , "modifiedTx" .= tmtModifiedTx t
      , "outcome" .= tmtOutcome t
      ]

instance ToJSON ThreatModelTraceOutcome where
  toJSON TMTOPassed =
    object ["status" .= ("passed" :: Text)]
  toJSON (TMTOFailed reason) =
    object ["status" .= ("failed" :: Text), "reason" .= reason]
  toJSON (TMTOSkipped reason) =
    object ["status" .= ("skipped" :: Text), "reason" .= reason]
  toJSON (TMTOError msg) =
    object ["status" .= ("error" :: Text), "message" .= msg]
