{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Escrow.Spec.Unit where

import Cardano.Api qualified as C
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.Utils (failOnError)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet qualified as Wallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Escrow.Scripts (escrowValidatorScript)
import Escrow.Validator (
  EscrowParams (..),
 )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

-------------------------------------------------------------------------------
-- Unit tests for the Escrow script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    []
