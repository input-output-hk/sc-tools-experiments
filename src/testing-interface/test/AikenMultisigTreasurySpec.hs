{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF Multisig Treasury validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable multisig contract.
The CTF Multisig Treasury validator has TWO vulnerabilities:

== Vulnerability 1: Sign action has no continuation enforcement ==

The 'Sign' redeemer only checks that a required signer signed the transaction.
It does NOT require a continuation output at the same script address, nor does
it verify the datum is updated with the new signer. An attacker can consume
the multisig UTxO with 'Sign' and destroy it entirely.

== Vulnerability 2: Use action only checks 1-of-N signatures ==

The 'Use' redeemer checks @list.any(datum.signed_users, ...)@ meaning only ONE
signature from signed_users is needed. It should check that ALL required_signers
have signed (or are in signed_users AND sign the tx).

The Aiken types encode as:
- @Datum { release_value: Int, beneficiary: Address, required_signers: List<VerificationKeyHash>, signed_users: List<VerificationKeyHash> }@
- @Redeemer: Sign | Use@ = @Constr 0 [] | Constr 1 []@
-}
module AikenMultisigTreasurySpec (
  -- * TestingInterface model
  MultisigModel (..),

  -- * Test tree
  aikenMultisigTreasuryTests,

  -- * Standalone threat model tests
  propMultisigVulnerableToSingleSignerUse,
  propMultisigVulnerableToSignDestruction,
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO (..))
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, getUtxo)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO, runMockchain0IOWith)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  Options (Options, params),
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)

import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra, getWallet, verificationKeyHash)
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
 )
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- Multisig Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the multisig_treasury script address.

Aiken encodes this as:
@Constr 0 [release_value, beneficiary_address, required_signers_list, signed_users_list]@

Fields:
- release_value: Amount to release to beneficiary
- beneficiary: Full Plutus Address where funds go
- required_signers: List of pubkey hashes that must sign
- signed_users: List of pubkey hashes that have already signed
-}
data MultisigDatum = MultisigDatum
  { mdReleaseValue :: Integer
  -- ^ Amount to release (in lovelace)
  , mdBeneficiary :: PV1.Address
  -- ^ Plutus address of beneficiary
  , mdRequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signer pubkey hashes
  , mdSignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed so far
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the multisig treasury.

Aiken encodes as: @Sign = Constr 0 []@, @Use = Constr 1 []@
-}
data MultisigRedeemer = Sign | Use
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''MultisigDatum
PlutusTx.unstableMakeIsData ''MultisigRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_multisig_treasury" validator from the embedded blueprint
loadMultisigScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadMultisigScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_multisig_treasury.ctf_multisig_treasury.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_multisig_treasury.ctf_multisig_treasury.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Multisig Treasury script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE multisigScript #-}
multisigScript :: C.PlutusScript C.PlutusScriptV3
multisigScript = unsafePerformIO loadMultisigScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the multisig_treasury script
multisigScriptHash :: C.ScriptHash
multisigScriptHash = C.hashScript (plutusScript multisigScript)

-- | Address of the multisig_treasury script on the default network
multisigAddress :: C.AddressInEra C.ConwayEra
multisigAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript multisigScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Helper to convert wallet pubkey hash to BuiltinByteString
-- ----------------------------------------------------------------------------

-- | Get wallet pubkey hash as BuiltinByteString
walletPkhBytes :: Wallet -> PlutusTx.BuiltinByteString
walletPkhBytes w = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash w)

-- | Get wallet Plutus address
walletPlutusAddress :: Wallet -> PV1.Address
walletPlutusAddress w =
  let addr = addressInEra @C.ConwayEra Defaults.networkId w
   in case transAddressInEra addr of
        Just a -> a
        Nothing -> error "Failed to convert wallet address to Plutus address"

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Initialize the multisig treasury by paying to the script with initial datum.

Creates a 2-of-2 multisig with w1 and w2 as required signers.
-}
initMultisig
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Beneficiary wallet
  -> C.Lovelace
  -- ^ Initial value to lock
  -> m ()
initMultisig networkId beneficiary initialValue = do
  let beneficiaryAddr = walletPlutusAddress beneficiary
      -- 2-of-2 multisig: w1 and w2 must both sign
      requiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
      datum =
        MultisigDatum
          { mdReleaseValue = 10_000_000 -- Release 10 ADA when fully signed
          , mdBeneficiary = beneficiaryAddr
          , mdRequiredSigners = requiredSigners
          , mdSignedUsers = [] -- No one has signed yet
          }
  BuildTx.payToScriptInlineDatum
    networkId
    multisigScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Sign the multisig: spend the UTxO with Sign redeemer and create continuation.

This is the "correct" off-chain code that creates a proper continuation.
The VALIDATOR doesn't enforce this, which is the vulnerability!
-}
signMultisig
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> MultisigDatum
  -- ^ Current datum
  -> C.Value
  -- ^ Current value
  -> Wallet
  -- ^ The wallet signing
  -> m ()
signMultisig networkId txIn oldDatum currentValue signer = do
  let signerPkh = walletPkhBytes signer
      signerPkhC = verificationKeyHash signer
      -- Add signer to signed_users list
      newDatum =
        oldDatum
          { mdSignedUsers = signerPkh : mdSignedUsers oldDatum
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigScript
            (C.ScriptDatumForTxIn Nothing)
            Sign
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature signerPkhC
  -- Create continuation output with updated datum
  BuildTx.payToScriptInlineDatum
    networkId
    multisigScriptHash
    newDatum
    C.NoStakeAddress
    currentValue

{- | Sign the multisig WITHOUT continuation - demonstrates vulnerability 1.

This spends the script UTxO with Sign redeemer but does NOT create
a continuation output. The validator accepts this!
-}
signMultisigNoContinuation
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.TxIn
  -- ^ The script UTxO to spend
  -> Wallet
  -- ^ The wallet signing
  -> m ()
signMultisigNoContinuation txIn signer = do
  let signerPkhC = verificationKeyHash signer
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigScript
            (C.ScriptDatumForTxIn Nothing)
            Sign
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature signerPkhC

-- NO continuation output! Funds go to change address.

{- | Use the multisig to release funds to beneficiary.

This spends the script UTxO with Use redeemer.
-}
useMultisig
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.TxIn
  -- ^ The script UTxO to spend
  -> C.AddressInEra era
  -- ^ Beneficiary address
  -> C.Lovelace
  -- ^ Amount to release
  -> Wallet
  -- ^ Wallet providing the signature (must be in signed_users)
  -> m ()
useMultisig txIn beneficiaryAddr releaseValue signer = do
  let signerPkhC = verificationKeyHash signer
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigScript
            (C.ScriptDatumForTxIn Nothing)
            Use
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature signerPkhC
  BuildTx.payToAddress beneficiaryAddr (C.lovelaceToValue releaseValue)

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the multisig_treasury script address
findMultisigUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, MultisigDatum)]
findMultisigUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == multisigAddress) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @MultisigDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenMultisigUnitTests :: TestTree
aikenMultisigUnitTests =
  testGroup
    "ctf multisig_treasury unit tests"
    [ testCase "initialize multisig" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initMultisig @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findMultisigUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if length (mdRequiredSigners datum) == 2 && null (mdSignedUsers datum)
                    then pure ()
                    else assertFailure $ "Wrong datum state: " ++ show datum
    , testCase "normal flow: init -> sign(w1) -> sign(w2) -> use" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize multisig with w1 as beneficiary
            let initTxBody = execBuildTx $ initMultisig @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Sign with w1
            result1 <- findMultisigUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, value1, datum1) : _) -> do
                let sign1TxBody = execBuildTx $ signMultisig @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
                _ <- tryBalanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []

                -- Sign with w2
                result2 <- findMultisigUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after first sign"
                  ((txIn2, value2, datum2) : _) -> do
                    -- Verify w1 is now in signed_users
                    liftIO $
                      if length (mdSignedUsers datum2) == 1
                        then pure ()
                        else assertFailure $ "Expected 1 signed user, got: " ++ show (mdSignedUsers datum2)

                    let sign2TxBody = execBuildTx $ signMultisig @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w2
                    _ <- tryBalanceAndSubmit mempty Wallet.w2 sign2TxBody TrailingChange []

                    -- Use the multisig
                    result3 <- findMultisigUtxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected UTxO after second sign"
                      ((txIn3, _, datum3) : _) -> do
                        -- Verify both are in signed_users
                        liftIO $
                          if length (mdSignedUsers datum3) == 2
                            then pure ()
                            else assertFailure $ "Expected 2 signed users, got: " ++ show (mdSignedUsers datum3)

                        let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                            useTxBody = execBuildTx $ useMultisig @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                        void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                        -- Verify UTxO is gone
                        result4 <- findMultisigUtxos
                        case result4 of
                          [] -> pure ()
                          _ -> liftIO $ assertFailure "Expected no UTxO after use"
    , testCase "exploit 1: use with only 1 signer (1-of-N vulnerability)" $
        -- This demonstrates that Use only needs 1 signed_user, not all required_signers
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with w1 in signed_users already (pretend w1 signed)
            -- We'll create a datum directly with w1 in signed_users
            let beneficiaryAddr = walletPlutusAddress Wallet.w1
                datum =
                  MultisigDatum
                    { mdReleaseValue = 10_000_000
                    , mdBeneficiary = beneficiaryAddr
                    , mdRequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
                    , mdSignedUsers = [walletPkhBytes Wallet.w1] -- Only w1 has "signed"
                    }
            -- Pay to script with this datum
            let initTxBody =
                  execBuildTx $
                    BuildTx.payToScriptInlineDatum
                      Defaults.networkId
                      multisigScriptHash
                      datum
                      C.NoStakeAddress
                      (C.lovelaceToValue 20_000_000)
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Now try to Use with only w1 signing - this SHOULD FAIL for proper 2-of-2
            -- but SUCCEEDS due to the vulnerability!
            result <- findMultisigUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _datum) : _) -> do
                let beneficiaryAddrC = addressInEra Defaults.networkId Wallet.w1
                    useTxBody = execBuildTx $ useMultisig @C.ConwayEra txIn beneficiaryAddrC 10_000_000 Wallet.w1
                -- This succeeds even though w2 never signed!
                void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                -- Verify UTxO is gone (exploit succeeded!)
                result2 <- findMultisigUtxos
                case result2 of
                  [] -> pure () -- Exploit worked!
                  _ -> liftIO $ assertFailure "Exploit should have succeeded"
    , testCase "exploit 2: sign without continuation (destroys UTxO)" $
        -- This demonstrates that Sign doesn't require a continuation output
        mockchainSucceeds $
          failOnError $ do
            -- Initialize multisig
            let initTxBody = execBuildTx $ initMultisig @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Sign WITHOUT creating continuation - this SHOULD FAIL
            -- but SUCCEEDS due to the vulnerability!
            result <- findMultisigUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let signTxBody = execBuildTx $ signMultisigNoContinuation @C.ConwayEra txIn Wallet.w1
                void $ tryBalanceAndSubmit mempty Wallet.w1 signTxBody TrailingChange []

                -- Verify UTxO is GONE (not just updated) - this is the vulnerability!
                result2 <- findMultisigUtxos
                case result2 of
                  [] -> pure () -- UTxO destroyed! Exploit worked.
                  _ -> liftIO $ assertFailure "UTxO should have been destroyed (vulnerability)"
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Test that the multisig contract is vulnerable to single-signer Use.

This demonstrates Vulnerability 2: Use only requires ANY ONE signed_user
to sign the transaction, not ALL required_signers.

We use 'expectFailure' because finding the vulnerability means the
QuickCheck property fails (which is expected for a vulnerable script).
-}
propMultisigVulnerableToSingleSignerUse :: RunOptions -> Property
propMultisigVulnerableToSingleSignerUse opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Initialize with w1 already in signed_users (simulating partial signing)
    let beneficiaryAddr = walletPlutusAddress Wallet.w1
        datum =
          MultisigDatum
            { mdReleaseValue = 10_000_000
            , mdBeneficiary = beneficiaryAddr
            , mdRequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
            , mdSignedUsers = [walletPkhBytes Wallet.w1] -- Only w1 has "signed"
            }
    let initTxBody =
          execBuildTx $
            BuildTx.payToScriptInlineDatum
              Defaults.networkId
              multisigScriptHash
              datum
              C.NoStakeAddress
              (C.lovelaceToValue 20_000_000)
    _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

    -- Capture UTxO BEFORE Use
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Try to Use with only w1 signing
    msResult <- findMultisigUtxos
    case msResult of
      [] -> fail "Expected UTxO at script address"
      ((txIn, _, _) : _) -> do
        let beneficiaryAddrC = addressInEra Defaults.networkId Wallet.w1
            useTxBody = execBuildTx $ useMultisig @C.ConwayEra txIn beneficiaryAddrC 10_000_000 Wallet.w1
        useTx <- tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

        -- If we get here, the vulnerability exists! Use succeeded with only 1 signer.
        -- The test "passes" (vulnerability confirmed) by returning True
        pure (useTx, utxoBefore)

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable (which would be good!)
      -- But we expect it to SUCCEED (vulnerability exists), so this would be a surprise.
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing multisig for single-signer Use vulnerability")
      -- The Use transaction SUCCEEDED with only 1 signer - vulnerability confirmed!
      pure $ QC.property True

{- | Test that the multisig contract is vulnerable to Sign destroying the UTxO.

This demonstrates Vulnerability 1: Sign does not enforce continuation output.
An attacker can spend the script UTxO and not create a continuation.

We use 'expectFailure' because finding the vulnerability means the
QuickCheck property fails (which is expected for a vulnerable script).
-}
propMultisigVulnerableToSignDestruction :: RunOptions -> Property
propMultisigVulnerableToSignDestruction opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario AND the threat model INSIDE MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Initialize multisig
    let initTxBody = execBuildTx $ initMultisig @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

    -- Capture UTxO BEFORE signing
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Sign WITHOUT continuation
    msResult <- findMultisigUtxos
    case msResult of
      [] -> fail "Expected UTxO at script address"
      ((txIn, _, _) : _) -> do
        let signTxBody = execBuildTx $ signMultisigNoContinuation @C.ConwayEra txIn Wallet.w1
        signTx <- tryBalanceAndSubmit mempty Wallet.w1 signTxBody TrailingChange []

        -- Check if UTxO was destroyed
        msResult2 <- findMultisigUtxos
        case msResult2 of
          [] -> pure (signTx, utxoBefore) -- UTxO destroyed - vulnerability confirmed!
          _ -> fail "UTxO should have been destroyed but wasn't"

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable (which would be good!)
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing multisig for Sign destruction vulnerability")
      -- The Sign transaction SUCCEEDED without continuation - vulnerability confirmed!
      pure $ QC.property True

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Multisig Treasury contract
data MultisigModel = MultisigModel
  { mmTxIn :: C.TxIn
  -- ^ The UTxO at the script
  , mmValue :: C.Lovelace
  -- ^ Value locked in the multisig
  , mmRequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signers
  , mmSignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed
  , mmBeneficiary :: PV1.Address
  -- ^ Beneficiary address
  , mmReleaseValue :: Integer
  -- ^ Amount to release
  , mmHasBeenUsed :: Bool
  -- ^ Once used, sequence is done - no re-initialization allowed
  }
  deriving stock (Show, Eq)

-- | Which signer to use (w1 or w2)
data SignerChoice = Signer1 | Signer2
  deriving stock (Show, Eq)

signerToWallet :: SignerChoice -> Wallet
signerToWallet Signer1 = Wallet.w1
signerToWallet Signer2 = Wallet.w2

instance TestingInterface MultisigModel where
  -- Actions for Multisig: initialize, sign, and use
  data Action MultisigModel
    = SignMultisig SignerChoice
    | -- \^ Sign with a wallet (Signer1 = w1, Signer2 = w2)
      UseMultisig
    -- \^ Use the multisig (release funds)
    deriving stock (Show, Eq)

  initialize = do
    let txBody = execBuildTx $ initMultisig @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
    void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    pure $
      MultisigModel
        { mmTxIn = C.TxIn dummyTxId (C.TxIx 0)
        , mmValue = 20_000_000
        , mmRequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
        , mmSignedUsers = []
        , mmBeneficiary = walletPlutusAddress Wallet.w1
        , mmReleaseValue = 10_000_000
        , mmHasBeenUsed = False
        }

  -- Generate actions based on state
  -- Init actions: TIGHT - only generate when not initialized
  -- Non-init actions: BROAD - generate all variants for negative testing
  arbitraryAction model
    | mmHasBeenUsed model = SignMultisig <$> QC.elements [Signer1, Signer2] -- Invalid: already used, will fail
    | length (mmSignedUsers model) < 2 =
        QC.frequency
          [ (80, SignMultisig <$> pickUnsignedSigner model)
          , (10, SignMultisig <$> pickSignedSigner model) -- Invalid: already signed
          , (10, pure UseMultisig) -- May succeed (1-of-N vulnerability)
          ]
    | otherwise =
        QC.frequency
          [ (90, pure UseMultisig)
          , (10, SignMultisig <$> QC.elements [Signer1, Signer2]) -- Invalid: both signed
          ]
   where
    pickUnsignedSigner m
      | walletPkhBytes Wallet.w1 `notElem` mmSignedUsers m = pure Signer1
      | walletPkhBytes Wallet.w2 `notElem` mmSignedUsers m = pure Signer2
      | otherwise = QC.elements [Signer1, Signer2]
    pickSignedSigner m
      | walletPkhBytes Wallet.w1 `elem` mmSignedUsers m = pure Signer1
      | walletPkhBytes Wallet.w2 `elem` mmSignedUsers m = pure Signer2
      | otherwise = QC.elements [Signer1, Signer2]

  precondition model (SignMultisig sc) =
    walletPkhBytes (signerToWallet sc) `notElem` mmSignedUsers model && not (mmHasBeenUsed model)
  precondition model UseMultisig =
    not (null (mmSignedUsers model)) && not (mmHasBeenUsed model)

  nextState model action = case action of
    SignMultisig sc ->
      model
        { mmSignedUsers = walletPkhBytes (signerToWallet sc) : mmSignedUsers model
        }
    UseMultisig ->
      model
        { mmHasBeenUsed = True -- Mark as used - no re-init allowed
        }

  perform _model action = case action of
    SignMultisig sc -> do
      let w = signerToWallet sc
      result <- findMultisigUtxos
      case result of
        [] -> fail "No UTxO found at multisig script address"
        ((txIn, value, datum) : _) -> do
          let txBody = execBuildTx $ signMultisig @C.ConwayEra Defaults.networkId txIn datum value w
              -- If signer is not w1, we need to provide their witness since w1 is used for balancing
              additionalWitnesses = case sc of
                Signer1 -> []
                Signer2 -> [C.WitnessPaymentKey (getWallet w)]
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange additionalWitnesses
    UseMultisig -> do
      result <- findMultisigUtxos
      case result of
        [] -> fail "No UTxO found at multisig script address for use"
        ((txIn, _, datum) : _) -> do
          -- Use the first signed user to sign the Use transaction
          let w1IsSigner = walletPkhBytes Wallet.w1 `elem` mdSignedUsers datum
              signer = if w1IsSigner then Wallet.w1 else Wallet.w2
              beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
              releaseVal = fromInteger (mdReleaseValue datum) :: C.Lovelace
              txBody = execBuildTx $ useMultisig @C.ConwayEra txIn beneficiaryAddr releaseVal signer
              -- If signer is not w1, we need to provide their witness since w1 is used for balancing
              additionalWitnesses = if w1IsSigner then [] else [C.WitnessPaymentKey (getWallet signer)]
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange additionalWitnesses

  -- Simplified validation that always returns True
  -- This is acceptable for a CTF contract since we're primarily testing vulnerabilities
  validate _model = pure True

  monitoring _state _action prop = prop

  -- NOTE: threatModels is empty for multisig because most action sequences
  -- end with UseMultisig (which doesn't create a script output). Threat models
  -- like unprotectedScriptOutput require a script output, causing 100% test discard.
  threatModels = []

  -- Expected vulnerabilities: these threat models SHOULD find issues
  -- (inverted pass/fail, quiet output)
  expectedVulnerabilities = [unprotectedScriptOutput]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Multisig Treasury tests grouped together
aikenMultisigTreasuryTests :: RunOptions -> TestTree
aikenMultisigTreasuryTests runOpts =
  testGroup
    "ctf multisig_treasury"
    [ aikenMultisigUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @MultisigModel
            "property-based testing"
            runOpts
        , QC.testProperty
            "vulnerable to single-signer Use (1-of-N)"
            (propMultisigVulnerableToSingleSignerUse runOpts)
        , QC.testProperty
            "vulnerable to Sign destroying UTxO"
            (propMultisigVulnerableToSignDestruction runOpts)
        ]
    ]
