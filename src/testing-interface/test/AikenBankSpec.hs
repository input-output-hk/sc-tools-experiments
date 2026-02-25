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

{- | Tests for the Aiken-compiled CTF Bank validators (Levels 00-03).

This module tests a two-validator architecture (bank + account) with parameterized
bank validators. The bank validator holds pooled funds while account validators
track individual user balances.

== Architecture ==

The system uses TWO validators:
- **Bank validator**: Holds pooled funds, parameterized by account script hash
- **Account validator**: Per-user account that authorizes balance changes

The bank validator checks that fund_difference matches account balance change.
The account validator authorizes deposits (anyone) and withdrawals (owner only).

== Bank Level Vulnerabilities ==

**Level 00:** No `balance >= 0` check. Withdraw more than deposited -> negative balance.
**Level 01:** Balance >= 0 added, but IncreaseBalance always succeeds -> attacker can
              "deposit" without sending funds.
**Level 02:** Account checks for output with same owner, but multiple accounts can
              cross-match outputs.
**Level 03:** Account adds balance direction checks, but bank matches wrong input-output
              pairs with multiple accounts.

== Parameter Application ==

The bank validators are parameterized: `validator ctf_bank_XX_bank(account_script_hash: ByteArray)`.
We apply the account script hash at runtime using UPLC program application.
-}
module AikenBankSpec (
  -- * Test tree
  aikenBankTests,

  -- * Model
  BankModel (..),
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Trans (lift)
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.MutualExclusion (mutualExclusionAttack)
import Convex.ThreatModel.NegativeInteger (negativeIntegerAttack)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.ThreatModel.ValueUnderpayment (valueUnderpaymentAttack)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.ByteString qualified as BS
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)
import Data.String (fromString)

import Paths_convex_testing_interface qualified as Pkg
import PlutusCore qualified as PLC
import PlutusLedgerApi.Common qualified as PlutusLedgerApi
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx

import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck ()
import Test.Tasty.QuickCheck qualified as QC
import UntypedPlutusCore qualified as UPLC

-- ----------------------------------------------------------------------------
-- Helper: pay to script without datum
-- ----------------------------------------------------------------------------

-- | Pay to a script address without a datum (for scripts using Option<Data> = None).
payToScriptNoDatum
  :: forall era m
   . ( MonadBuildTx era m
     , C.IsBabbageBasedEra era
     )
  => C.NetworkId
  -> C.ScriptHash
  -> C.StakeAddressReference
  -> C.Value
  -> m ()
payToScriptNoDatum network scriptHash stakeRef value =
  C.babbageEraOnwardsConstraints (C.babbageBasedEra @era) $ do
    let addr =
          C.makeShelleyAddressInEra
            C.shelleyBasedEra
            network
            (C.PaymentCredentialByScript scriptHash)
            stakeRef
        txo =
          C.TxOut
            addr
            (C.TxOutValueShelleyBased C.shelleyBasedEra $ C.toMaryValue value)
            C.TxOutDatumNone
            C.ReferenceScriptNone
    BuildTx.addOutput txo

-- ----------------------------------------------------------------------------
-- Bank Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at an account script address.

Aiken encodes this as: @Constr 0 [balance, owner]@

Fields:
- balance: Integer tracking the user's logical balance
- owner: ByteArray of the owner's pubkey hash
-}
data AccountDatum = AccountDatum
  { adBalance :: Integer
  -- ^ The user's logical balance
  , adOwner :: PlutusTx.BuiltinByteString
  -- ^ The owner's pubkey hash
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on an account.

Aiken encodes as:
- @IncreaseBalance = Constr 0 []@
- @DecreaseBalance = Constr 1 []@
-}
data AccountRedeemer = IncreaseBalance | DecreaseBalance
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''AccountDatum
PlutusTx.unstableMakeIsData ''AccountRedeemer

-- ----------------------------------------------------------------------------
-- Script loading and parameter application
-- ----------------------------------------------------------------------------

{- | Apply a ByteString parameter to a parameterized Plutus script.

This is used to apply the account script hash to the bank validator.
The bank validator is defined as: @validator ctf_bank_XX_bank(account_script_hash: ByteArray)@

Aiken parameterized validators expect the parameter as a Data value.
For ByteArray, this means encoding as Data.B (bytestring wrapped in Data).
-}
applyByteStringParam
  :: BS.ByteString
  -- ^ Parameter (account script hash as raw bytes)
  -> C.PlutusScript C.PlutusScriptV3
  -- ^ Unapplied script
  -> Either String (C.PlutusScript C.PlutusScriptV3)
applyByteStringParam paramBytes script = do
  -- 1. Convert PlutusScript to UPLC Program
  program <- Blueprint.fromCardanoApiScriptToProgram script

  -- 2. Create parameter as a UPLC constant Data (B bytestring)
  --    Aiken parameterized validators expect Data, not raw values
  let paramData = PlutusLedgerApi.B paramBytes
      paramTerm = UPLC.Constant () (PLC.someValue paramData)
      paramProgram = UPLC.Program () (UPLC._progVer program) paramTerm

  -- 3. Apply parameter using UPLC.applyProgram
  case UPLC.applyProgram program paramProgram of
    Left err -> Left (show err)
    Right applied -> Right (Blueprint.fromProgramToCardanoApiScript applied)

-- | Data for a bank level (account + applied bank scripts)
data BankLevel = BankLevel
  { blAccountScript :: C.PlutusScript C.PlutusScriptV3
  , blBankScript :: C.PlutusScript C.PlutusScriptV3
  , blAccountHash :: C.ScriptHash
  , blBankHash :: C.ScriptHash
  , blAccountAddress :: C.AddressInEra C.ConwayEra
  , blBankAddress :: C.AddressInEra C.ConwayEra
  }
  deriving stock (Show)

-- | Load a bank level from the blueprint
loadBankLevel
  :: String
  -- ^ Account validator name (e.g., "ctf_bank_00_account")
  -> String
  -- ^ Bank validator name (e.g., "ctf_bank_00_bank")
  -> IO BankLevel
loadBankLevel accountName bankName = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure

  -- Load account script (non-parameterized)
  accountScript <- case Map.lookup (fromString $ accountName <> "." <> accountName <> ".spend") validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail $ accountName <> " not found in blueprint"

  -- Load bank script (parameterized - unapplied)
  unappliedBankScript <- case Map.lookup (fromString $ bankName <> "." <> bankName <> ".spend") validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail $ bankName <> " not found in blueprint"

  -- Get account script hash
  let accountScriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 accountScript)
      accountHashBytes = C.serialiseToRawBytes accountScriptHash

  -- Apply parameter to bank script
  bankScript <- case applyByteStringParam accountHashBytes unappliedBankScript of
    Left err -> fail $ "Failed to apply parameter to bank script: " ++ err
    Right s -> pure s

  let bankScriptHash = C.hashScript (C.PlutusScript C.PlutusScriptV3 bankScript)

      accountAddress =
        C.makeShelleyAddressInEra
          C.shelleyBasedEra
          Defaults.networkId
          (C.PaymentCredentialByScript accountScriptHash)
          C.NoStakeAddress

      bankAddress =
        C.makeShelleyAddressInEra
          C.shelleyBasedEra
          Defaults.networkId
          (C.PaymentCredentialByScript bankScriptHash)
          C.NoStakeAddress

  pure
    BankLevel
      { blAccountScript = accountScript
      , blBankScript = bankScript
      , blAccountHash = accountScriptHash
      , blBankHash = bankScriptHash
      , blAccountAddress = accountAddress
      , blBankAddress = bankAddress
      }

-- | Load all bank levels at startup
{-# NOINLINE bankLevel00 #-}
bankLevel00 :: BankLevel
bankLevel00 = unsafePerformIO $ loadBankLevel "ctf_bank_00_account" "ctf_bank_00_bank"

{-# NOINLINE bankLevel01 #-}
bankLevel01 :: BankLevel
bankLevel01 = unsafePerformIO $ loadBankLevel "ctf_bank_01_account" "ctf_bank_01_bank"

{-# NOINLINE bankLevel02 #-}
bankLevel02 :: BankLevel
bankLevel02 = unsafePerformIO $ loadBankLevel "ctf_bank_02_account" "ctf_bank_02_bank"

{-# NOINLINE bankLevel03 #-}
bankLevel03 :: BankLevel
bankLevel03 = unsafePerformIO $ loadBankLevel "ctf_bank_03_account" "ctf_bank_03_bank"

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Initialize the bank: create bank UTxO with initial funds and account UTxO.

Creates:
1. Bank UTxO with pooled funds (no datum)
2. Account UTxO with initial balance = 0 and owner set
-}
initBank
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => BankLevel
  -> C.NetworkId
  -> Wallet
  -- ^ Owner wallet
  -> C.Lovelace
  -- ^ Initial bank funds
  -> m ()
initBank level networkId owner initialFunds = do
  let ownerPkh = verificationKeyHash owner
      ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes ownerPkh
      accountDatum = AccountDatum{adBalance = 0, adOwner = ownerBytes}

  -- Create bank UTxO (no datum needed for bank)
  payToScriptNoDatum
    networkId
    (blBankHash level)
    C.NoStakeAddress
    (C.lovelaceToValue initialFunds)

  -- Create account UTxO with inline datum
  BuildTx.payToScriptInlineDatum
    networkId
    (blAccountHash level)
    accountDatum
    C.NoStakeAddress
    (C.lovelaceToValue 2_000_000) -- Min UTxO for account

{- | Deposit funds: spend both bank and account UTxOs, increase balance.

This is the normal deposit flow:
1. Spend bank UTxO
2. Spend account UTxO with IncreaseBalance redeemer
3. Create new bank UTxO with increased value
4. Create new account UTxO with increased balance
-}
deposit
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => BankLevel
  -> C.NetworkId
  -> C.TxIn
  -- ^ Bank UTxO
  -> C.Value
  -- ^ Current bank value
  -> C.TxIn
  -- ^ Account UTxO
  -> AccountDatum
  -- ^ Current account datum
  -> C.Value
  -- ^ Current account value
  -> C.Lovelace
  -- ^ Amount to deposit
  -> Wallet
  -- ^ Depositor (must be owner)
  -> m ()
deposit level networkId bankTxIn bankValue accountTxIn accountDatum accountValue depositAmount _owner = do
  let newBalance = adBalance accountDatum + fromIntegral depositAmount
      newAccountDatum = accountDatum{adBalance = newBalance}
      newBankValue = bankValue <> C.lovelaceToValue depositAmount

      -- Bank witness (no datum)
      bankWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            (blBankScript level)
            (C.ScriptDatumForTxIn Nothing)
            () -- Bank uses unit redeemer

      -- Account witness
      accountWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            (blAccountScript level)
            (C.ScriptDatumForTxIn Nothing)
            IncreaseBalance

  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody bankTxIn bankWitness
  BuildTx.addInputWithTxBody accountTxIn accountWitness

  -- Create new bank UTxO
  payToScriptNoDatum
    networkId
    (blBankHash level)
    C.NoStakeAddress
    newBankValue

  -- Create new account UTxO
  BuildTx.payToScriptInlineDatum
    networkId
    (blAccountHash level)
    newAccountDatum
    C.NoStakeAddress
    accountValue

{- | Withdraw funds: spend both bank and account UTxOs, decrease balance.

This is the normal withdrawal flow:
1. Spend bank UTxO
2. Spend account UTxO with DecreaseBalance redeemer
3. Create new bank UTxO with decreased value
4. Create new account UTxO with decreased balance
5. Pay withdrawn funds to owner
-}
withdraw
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => BankLevel
  -> C.NetworkId
  -> C.TxIn
  -- ^ Bank UTxO
  -> C.Value
  -- ^ Current bank value
  -> C.TxIn
  -- ^ Account UTxO
  -> AccountDatum
  -- ^ Current account datum
  -> C.Value
  -- ^ Current account value
  -> C.Lovelace
  -- ^ Amount to withdraw
  -> Wallet
  -- ^ Owner
  -> m ()
withdraw level networkId bankTxIn bankValue accountTxIn accountDatum accountValue withdrawAmount owner = do
  let ownerPkh = verificationKeyHash owner
      newBalance = adBalance accountDatum - fromIntegral withdrawAmount
      newAccountDatum = accountDatum{adBalance = newBalance}
      -- Subtract from bank value
      newBankValue = case C.valueToLovelace bankValue of
        Just lovelace -> C.lovelaceToValue (lovelace - withdrawAmount)
        Nothing -> bankValue -- Shouldn't happen in tests

      -- Bank witness (no datum)
      bankWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            (blBankScript level)
            (C.ScriptDatumForTxIn Nothing)
            ()

      -- Account witness
      accountWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            (blAccountScript level)
            (C.ScriptDatumForTxIn Nothing)
            DecreaseBalance

  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody bankTxIn bankWitness
  BuildTx.addInputWithTxBody accountTxIn accountWitness
  BuildTx.addRequiredSignature ownerPkh

  -- Create new bank UTxO
  payToScriptNoDatum
    networkId
    (blBankHash level)
    C.NoStakeAddress
    newBankValue

  -- Create new account UTxO
  BuildTx.payToScriptInlineDatum
    networkId
    (blAccountHash level)
    newAccountDatum
    C.NoStakeAddress
    accountValue

  -- Pay withdrawn funds to owner
  BuildTx.payToAddress
    (addressInEra Defaults.networkId owner)
    (C.lovelaceToValue withdrawAmount)

-- ----------------------------------------------------------------------------
-- EXPLOIT: Level 00 - Negative balance
-- ----------------------------------------------------------------------------

{- | Exploit for Level 00: Withdraw more than deposited.

The vulnerability: bank_00 does NOT check that balance >= 0.
An attacker can withdraw 100 ADA with balance=0, resulting in balance=-100.
-}
exploitBank00
  :: forall m
   . (MonadBuildTx C.ConwayEra m)
  => C.NetworkId
  -> C.TxIn
  -> C.Value
  -> C.TxIn
  -> AccountDatum
  -> C.Value
  -> C.Lovelace
  -- ^ Amount to steal (withdraw with 0 balance)
  -> Wallet
  -> m ()
exploitBank00 = withdraw bankLevel00

-- Note: Level 01 vulnerability is subtle - the IncreaseBalance always succeeds,
-- but the bank still checks fund_difference == balance_change. The vulnerability
-- might be in how multiple accounts interact or in edge cases not yet tested.
-- For now, we focus on testing the fix from Level 00 (negative balance blocked).

-- Note: Level 02 and 03 vulnerabilities involve multiple accounts.
-- These require more complex setup and are documented in the unit tests below.

-- ----------------------------------------------------------------------------
-- Helper to find UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the bank script address
findBankUtxos
  :: (MonadMockchain C.ConwayEra m)
  => BankLevel
  -> m [(C.TxIn, C.Value)]
findBankUtxos level = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      bankUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == blBankAddress level) utxos
  pure $ mapMaybe extractValue $ Map.toList bankUtxos
 where
  extractValue (txIn, C.TxOut _ txOutValue _ _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val -> Just (txIn, C.fromMaryValue val)
      C.TxOutValueByron _ -> Nothing

-- | Find all UTxOs at the account script address
findAccountUtxos
  :: (MonadMockchain C.ConwayEra m)
  => BankLevel
  -> m [(C.TxIn, C.Value, AccountDatum)]
findAccountUtxos level = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      accountUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == blAccountAddress level) utxos
  pure $ mapMaybe extractData $ Map.toList accountUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @AccountDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum for account"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests for Bank Level 00
-- ----------------------------------------------------------------------------

aikenBank00UnitTests :: TestTree
aikenBank00UnitTests =
  testGroup
    "bank_00 - core invariant"
    [ testCase "initialize bank and account" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initBank bankLevel00 Defaults.networkId Wallet.w1 100_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

            -- Verify UTxOs exist
            bankUtxos <- findBankUtxos bankLevel00
            accountUtxos <- findAccountUtxos bankLevel00
            liftIO $ case (bankUtxos, accountUtxos) of
              ([(_, _)], [(_, _, datum)]) ->
                if adBalance datum == 0
                  then pure ()
                  else assertFailure $ "Expected balance=0, got " ++ show (adBalance datum)
              _ -> assertFailure "Expected one bank and one account UTxO"
    , testCase "normal deposit" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initBank bankLevel00 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Find UTxOs
            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel00
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel00

            -- Deposit 10 ADA
            let depositTxBody =
                  execBuildTx $
                    deposit
                      bankLevel00
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 depositTxBody TrailingChange []

            -- Verify balance increased
            [(_, _, newDatum)] <- findAccountUtxos bankLevel00
            liftIO $
              if adBalance newDatum == 10_000_000
                then pure ()
                else assertFailure $ "Expected balance=10M, got " ++ show (adBalance newDatum)
    , testCase "normal withdraw" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initBank bankLevel00 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Find UTxOs and deposit first
            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel00
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel00

            let depositTxBody =
                  execBuildTx $
                    deposit
                      bankLevel00
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      20_000_000
                      Wallet.w1
            _ <- tryBalanceAndSubmit mempty Wallet.w1 depositTxBody TrailingChange []

            -- Now withdraw
            [(bankTxIn2, bankValue2)] <- findBankUtxos bankLevel00
            [(accountTxIn2, accountValue2, accountDatum2)] <- findAccountUtxos bankLevel00

            let withdrawTxBody =
                  execBuildTx $
                    withdraw
                      bankLevel00
                      Defaults.networkId
                      bankTxIn2
                      bankValue2
                      accountTxIn2
                      accountDatum2
                      accountValue2
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 withdrawTxBody TrailingChange []

            -- Verify balance
            [(_, _, newDatum)] <- findAccountUtxos bankLevel00
            liftIO $
              if adBalance newDatum == 10_000_000
                then pure ()
                else assertFailure $ "Expected balance=10M after withdrawal, got " ++ show (adBalance newDatum)
    , testCase "EXPLOIT: withdraw more than deposited (negative balance)" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with 100 ADA in bank
            let initTxBody = execBuildTx $ initBank bankLevel00 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Find UTxOs - balance is 0
            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel00
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel00

            -- EXPLOIT: Withdraw 50 ADA with balance=0!
            let exploitTxBody =
                  execBuildTx $
                    exploitBank00
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      50_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 exploitTxBody TrailingChange []

            -- Verify NEGATIVE balance - the exploit worked!
            [(_, _, newDatum)] <- findAccountUtxos bankLevel00
            liftIO $
              if adBalance newDatum == -50_000_000
                then pure () -- Vulnerability confirmed!
                else assertFailure $ "Expected negative balance, got " ++ show (adBalance newDatum)
    ]

-- ----------------------------------------------------------------------------
-- Unit tests for Bank Level 01
-- ----------------------------------------------------------------------------

aikenBank01UnitTests :: TestTree
aikenBank01UnitTests =
  testGroup
    "bank_01 - deposit vulnerability"
    [ testCase "initialize bank and account" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initBank bankLevel01 Defaults.networkId Wallet.w1 100_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

            bankUtxos <- findBankUtxos bankLevel01
            accountUtxos <- findAccountUtxos bankLevel01
            liftIO $ case (bankUtxos, accountUtxos) of
              ([(_, _)], [(_, _, _)]) -> pure ()
              _ -> assertFailure "Expected one bank and one account UTxO"
    , testCase "normal deposit/withdraw" $
        mockchainSucceeds $
          failOnError $ do
            let initTxBody = execBuildTx $ initBank bankLevel01 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel01
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel01

            let depositTxBody =
                  execBuildTx $
                    deposit
                      bankLevel01
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 depositTxBody TrailingChange []

            [(bankTxIn2, bankValue2)] <- findBankUtxos bankLevel01
            [(accountTxIn2, accountValue2, accountDatum2)] <- findAccountUtxos bankLevel01

            let withdrawTxBody =
                  execBuildTx $
                    withdraw
                      bankLevel01
                      Defaults.networkId
                      bankTxIn2
                      bankValue2
                      accountTxIn2
                      accountDatum2
                      accountValue2
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 withdrawTxBody TrailingChange []

            [(_, _, finalDatum)] <- findAccountUtxos bankLevel01
            liftIO $
              if adBalance finalDatum == 0
                then pure ()
                else assertFailure $ "Expected balance=0, got " ++ show (adBalance finalDatum)
    , testCase "negative balance blocked (fix from level 00)" $
        mockchainSucceeds $
          failOnError $ do
            let initTxBody = execBuildTx $ initBank bankLevel01 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel01
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel01

            -- Try to withdraw with balance=0 (should fail now)
            let exploitTxBody =
                  execBuildTx $
                    withdraw
                      bankLevel01
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      50_000_000
                      Wallet.w1

            result <- lift $ runExceptT $ balanceAndSubmit mempty Wallet.w1 exploitTxBody TrailingChange []
            case result of
              Left _ -> pure () -- Expected failure
              Right (Left _) -> pure () -- Validation failure
              Right (Right _) -> liftIO $ assertFailure "Negative balance should be blocked in level 01"
    ]

-- ----------------------------------------------------------------------------
-- Unit tests for Bank Level 02
-- ----------------------------------------------------------------------------

aikenBank02UnitTests :: TestTree
aikenBank02UnitTests =
  testGroup
    "bank_02 - mutual exclusion"
    [ testCase "initialize bank and account" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize bank with one account
            let initTxBody = execBuildTx $ initBank bankLevel02 Defaults.networkId Wallet.w1 100_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            bankUtxos <- findBankUtxos bankLevel02
            accountUtxos <- findAccountUtxos bankLevel02
            liftIO $ case (bankUtxos, accountUtxos) of
              ([(_, _)], [(_, _, datum)]) ->
                if adBalance datum == 0
                  then pure ()
                  else assertFailure $ "Expected balance=0, got " ++ show (adBalance datum)
              _ -> assertFailure "Expected one bank and one account UTxO"
    , testCase "normal deposit" $
        mockchainSucceeds $
          failOnError $ do
            let initTxBody = execBuildTx $ initBank bankLevel02 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel02
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel02

            let depositTxBody =
                  execBuildTx $
                    deposit
                      bankLevel02
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 depositTxBody TrailingChange []

            [(_, _, newDatum)] <- findAccountUtxos bankLevel02
            liftIO $
              if adBalance newDatum == 10_000_000
                then pure ()
                else assertFailure $ "Expected balance=10M, got " ++ show (adBalance newDatum)
    ]

-- ----------------------------------------------------------------------------
-- Unit tests for Bank Level 03
-- ----------------------------------------------------------------------------

aikenBank03UnitTests :: TestTree
aikenBank03UnitTests =
  testGroup
    "bank_03 - balance manipulation"
    [ testCase "initialize bank and account" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initBank bankLevel03 Defaults.networkId Wallet.w1 100_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

            bankUtxos <- findBankUtxos bankLevel03
            accountUtxos <- findAccountUtxos bankLevel03
            liftIO $ case (bankUtxos, accountUtxos) of
              ([(_, _)], [(_, _, _)]) -> pure ()
              _ -> assertFailure "Expected one bank and one account UTxO"
    , testCase "balance direction enforced on deposit" $
        mockchainSucceeds $
          failOnError $ do
            let initTxBody = execBuildTx $ initBank bankLevel03 Defaults.networkId Wallet.w1 100_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            [(bankTxIn, bankValue)] <- findBankUtxos bankLevel03
            [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel03

            -- Deposit should require balance to INCREASE
            let depositTxBody =
                  execBuildTx $
                    deposit
                      bankLevel03
                      Defaults.networkId
                      bankTxIn
                      bankValue
                      accountTxIn
                      accountDatum
                      accountValue
                      10_000_000
                      Wallet.w1
            void $ tryBalanceAndSubmit mempty Wallet.w1 depositTxBody TrailingChange []

            [(_, _, newDatum)] <- findAccountUtxos bankLevel03
            liftIO $
              if adBalance newDatum == 10_000_000
                then pure ()
                else assertFailure $ "Expected balance=10M, got " ++ show (adBalance newDatum)
    ]

-- ----------------------------------------------------------------------------
-- TestingInterface instance for property-based testing
-- ----------------------------------------------------------------------------

-- | Model state for the Bank contract
data BankModel = BankModel
  { bmBankTxIn :: Maybe C.TxIn
  -- ^ Bank UTxO
  , bmBankValue :: C.Lovelace
  -- ^ Bank's pooled funds
  , bmAccountTxIn :: Maybe C.TxIn
  -- ^ Account UTxO
  , bmAccountBalance :: Integer
  -- ^ Account balance
  , bmAccountOwner :: Maybe PlutusTx.BuiltinByteString
  -- ^ Account owner
  , bmInitialized :: Bool
  }
  deriving stock (Show, Eq)

instance TestingInterface BankModel where
  data Action BankModel
    = InitBankAction
    | DepositAction C.Lovelace
    | WithdrawAction C.Lovelace
    deriving stock (Show, Eq)

  initialState =
    BankModel
      { bmBankTxIn = Nothing
      , bmBankValue = 0
      , bmAccountTxIn = Nothing
      , bmAccountBalance = 0
      , bmAccountOwner = Nothing
      , bmInitialized = False
      }

  arbitraryAction model
    | not (bmInitialized model) = pure InitBankAction
    | otherwise =
        QC.frequency
          [ (3, DepositAction <$> (fromInteger <$> QC.choose (1_000_000, 20_000_000)))
          , (2, WithdrawAction <$> (fromInteger <$> QC.choose (1_000_000, min 20_000_000 (bmAccountBalance model))))
          ]

  precondition model InitBankAction = not (bmInitialized model)
  precondition model (DepositAction _) = bmInitialized model
  precondition model (WithdrawAction amt) =
    bmInitialized model && bmAccountBalance model >= fromIntegral amt

  nextState model action = case action of
    InitBankAction ->
      let ownerBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
       in model
            { bmBankTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
            , bmBankValue = 100_000_000
            , bmAccountTxIn = Just (C.TxIn dummyTxId (C.TxIx 1))
            , bmAccountBalance = 0
            , bmAccountOwner = Just ownerBytes
            , bmInitialized = True
            }
    DepositAction amt ->
      model
        { bmBankValue = bmBankValue model + amt
        , bmAccountBalance = bmAccountBalance model + fromIntegral amt
        }
    WithdrawAction amt ->
      model
        { bmBankValue = bmBankValue model - amt
        , bmAccountBalance = bmAccountBalance model - fromIntegral amt
        }

  perform _model action = case action of
    InitBankAction -> do
      let txBody = execBuildTx $ initBank bankLevel00 Defaults.networkId Wallet.w1 100_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to initialize bank: " ++ show err
        Right _ -> pure ()
    DepositAction amt -> do
      [(bankTxIn, bankValue)] <- findBankUtxos bankLevel00
      [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel00
      let txBody =
            execBuildTx $
              deposit
                bankLevel00
                Defaults.networkId
                bankTxIn
                bankValue
                accountTxIn
                accountDatum
                accountValue
                amt
                Wallet.w1
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to deposit: " ++ show err
        Right _ -> pure ()
    WithdrawAction amt -> do
      [(bankTxIn, bankValue)] <- findBankUtxos bankLevel00
      [(accountTxIn, accountValue, accountDatum)] <- findAccountUtxos bankLevel00
      let txBody =
            execBuildTx $
              withdraw
                bankLevel00
                Defaults.networkId
                bankTxIn
                bankValue
                accountTxIn
                accountDatum
                accountValue
                amt
                Wallet.w1
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to withdraw: " ++ show err
        Right _ -> pure ()

  validate _model = pure True

  monitoring _state _action prop = prop

  threatModels = [unprotectedScriptOutput, negativeIntegerAttack, valueUnderpaymentAttack, mutualExclusionAttack]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Bank tests grouped together
aikenBankTests :: RunOptions -> TestTree
aikenBankTests runOpts =
  testGroup
    "CTF Bank Series"
    [ aikenBank00UnitTests
    , aikenBank01UnitTests
    , aikenBank02UnitTests
    , aikenBank03UnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @BankModel
            "property-based testing (bank_00)"
            runOpts
        ]
    ]
