{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Auction.Spec.Attacks where

import Auction.Scripts (auctionValidatorScript)
import Auction.Utils (getTxOutValue, getWalletAda, mintingScript, utxosAt)
import Auction.Validator (AuctionDatum (AuctionDatum), AuctionParams (..), AuctionRedeemer (..), Bid (Bid, bAddr, bAmount, bPkh), hugeValidatorScript)
import Cardano.Api qualified as C
import Control.Monad (forM_, void)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot, singleUTxO)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (paymentTo, tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.MonadLog (MonadLog, MonadLogIgnoreT (runMonadLogIgnoreT), logDebug, logDebugS, runMonadLogKatip, withKatipLogging)
import Convex.PlutusLedger.V1 (transPubKeyHash, unTransAssetName)
import Convex.Utils (failOnError)
import Convex.Wallet (verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Data.ByteString.Char8 (pack)
import Katip (Severity (..))
import PlutusLedgerApi.Common qualified as PlutusTx
import PlutusLedgerApi.V1 (CurrencySymbol (..), POSIXTime (..), tokenName)
import PlutusTx.Builtins qualified as BI
import PlutusTx.Builtins qualified as PlutusTx
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

attackTests :: TestTree
attackTests =
  testGroup
    "attack tests"
    [ testCase -- example of how to use logging in a test
        "SAA-0001: Set highest bid on deployment with value (should fail, but allows)"
        ( withKatipLogging DebugS "production" "tests" $ \katipConfig ->
            mockchainSucceeds $ failOnError $ runMonadLogKatip katipConfig $ setHighestOnDeploymentTest 5_000_000
        )
    , testCase
        "SAA-0002: Set highest bid on deployment with a small value and try to place a bid (should fail, but allows)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT $ setHighestOnDeploymentBidTest 850_000)
    , testCase
        "SAA-0002: Set highest bid on deployment with a small value and try to payout (not allowed)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT $ setHighestOnDeploymentPayoutTest 850_000)
    , testCase
        "SAA-0003: Set highest bid on deployment with the same value in the produced utxo (should fail, but allows)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT setHighestOnDeploymentSameValueTest)
    , testCase
        "SAA-0004: Add extra fields on BuiltinData level on deployment and try to bid (fails on Bid with parsing error)"
        (mockchainFails (failOnError $ runMonadLogIgnoreT $ extraFieldOnDatumBidTest 8044) (\_ -> pure ()))
    , testCase
        "SAA-0004: Add extra fields on BuiltinData level on deployment and try to payout (fails on Payout with parsing error)"
        (mockchainFails (failOnError $ runMonadLogIgnoreT $ extraFieldOnDatumPayoutTest 8044) (\_ -> pure ()))
    , testCase
        "SAA-0005: Try to place a bid with a reference script that exceeds the maximum allowed size"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT addReferenceScriptBidTest)
    , testCase
        "SAA-0005: Try to place a bid and payout with a reference script that exceeds the maximum allowed size"
        (mockchainFails (failOnError $ runMonadLogIgnoreT addReferenceScriptPayoutTest) (\_ -> pure ()))
    , testCase
        "SAA-0006: The Auctioned Token is not present at the produced utxo upon deployment (allows locking, but fails on bid)"
        (mockchainFails (failOnError $ runMonadLogIgnoreT tokenNotPresentBidTest) (\_ -> pure ()))
    , testCase
        "SAA-0006: The Auctioned Token is not present at the produced utxo upon deployment (allows locking and payout)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT tokenNotPresentPayoutTest)
    , testCase
        "SAA-0006: The Auctioned Token doesn't exists in the seller wallet and is not present at the produced utxo (should fail)"
        (mockchainFails (failOnError $ runMonadLogIgnoreT tokenDoNotExistPayoutTest) (\_ -> pure ()))
    , testCase
        "SAA-0007: Other tokens are present at the produced utxo upon deployment (allows locking, bidding and payout)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT otherTokensTest)
    , testCase
        "SAA-0008: Upon deployment Ada at produced utxo is bigger than the minimum bid"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT moreAdaThanMinBidTest)
    , testCase
        "SAA-0009: Tries to bid when Ada deployed at produced utxo is high, but smaller than the minimum bid"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT firstBidUnderpaymentBidTest)
    , testCase
        "SAA-0009: Tries to payout when Ada deployed at produced utxo is high, but smaller than the minimum bid"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT firstBidUnderpaymentPayoutTest)
    , testCase
        "SAA-0010: Bid placed after end time due to transaction validity range (should fail)"
        (mockchainFails (failOnError $ runMonadLogIgnoreT $ endTimeBeforeBidTest 25) (\_ -> pure ()))
    , testCase
        "SAA-0010: Payout placed after end time when no bids allowed due to transaction validity range"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT payoutWithNoBidsTest)
    , testCase
        "SAA-0011: Uppon bidding, address exceeds 32 bytes, and tries to place another bid (should fail, but is not)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT wrongAddressBidTest)
    , testCase
        "SAA-0011: Uppon bidding, address exceeds 32 bytes, and tries to payout (should fail, but is not)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT wrongAddressPayoutTest)
    , testCase
        "SAA-0012: Try to flood the contract with a large amount of other tokens in the bid and tries another bid (fails when decrease Unit steps)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT additionalTokensOnBidTest)
    , -- (mockchainFails (failOnError $ runMonadLogIgnoreT additionalTokensOnBidTest) (\_ -> pure ()))
      testCase
        "SAA-0012: Try to flood the contract with a large amount of other tokens in the bid and tries to payout (should fail, but is not)"
        (mockchainSucceeds $ failOnError $ runMonadLogIgnoreT additionalTokensOnBidPayoutTest)
    ]

-------------------------------------------------------------------------------
-- Attack Tests
-------------------------------------------------------------------------------

-- | SAA-0001: Set highest bid on deployment with some value
setHighestOnDeploymentTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace
  -> m ()
setHighestOnDeploymentTest value = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator
  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Create a fake bid to set as highest on deployment
  let fakeBidder = MockWallet.w1
      fakeBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId fakeBidder
          , bPkh = transPubKeyHash $ verificationKeyHash fakeBidder
          , bAmount = fromInteger $ C.unCoin value
          }

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum (Just fakeBid)
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 10_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 10_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  let bidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Refund the fake bidder exactly the fake bid amount
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId fakeBidder) (C.lovelaceToValue value)
          -- Pay to script with new datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  return ()

-- | SAA-0002: Set highest bid on deployment with some small value and try to place a bid
setHighestOnDeploymentBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace
  -> m ()
setHighestOnDeploymentBidTest value = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA at the beginning: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA at the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Create a fake bid to set as highest on deployment
  let fakeBidder = MockWallet.w1
      fakeBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId fakeBidder
          , bPkh = transPubKeyHash $ verificationKeyHash fakeBidder
          , bAmount = fromInteger $ C.unCoin value
          }

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum (Just fakeBid)
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 10_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 10_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  let bidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Refund the fake bidder exactly the fake bid amount
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId fakeBidder) (C.lovelaceToValue value)
          -- Pay to script with new datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA at the end: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA at the end: " <> show ada

  return ()

-- | SAA-0002: Set highest bid on deployment with some small value and try to payout
setHighestOnDeploymentPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace
  -> m ()
setHighestOnDeploymentPayoutTest value = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA on the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Create a fake bid to set as highest on deployment
  let fakeBidder = MockWallet.w1
      fakeBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId fakeBidder
          , bPkh = transPubKeyHash $ verificationKeyHash fakeBidder
          , bAmount = fromInteger $ C.unCoin value
          }

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum (Just fakeBid)
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- Payout with a fake Bid on deployment
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue value)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA on the end: " <> show ada

  return ()

-- | SAA-0003: Set highest bid on deployment with the same value in the produced utxo
setHighestOnDeploymentSameValueTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
setHighestOnDeploymentSameValueTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA on the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Create a fake bid to set as highest on deployment
  let fakeBidder = MockWallet.w1
      fakeBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId fakeBidder
          , bPkh = transPubKeyHash $ verificationKeyHash fakeBidder
          , bAmount = 5_000_000
          }

  -- Initial datum: using a fake bid with the same value as the one in the locked UTxO
  let initialDatum = AuctionDatum (Just fakeBid)
  let initialValue = BuildTx.assetValue policyId an 1 <> C.lovelaceToValue 5_000_000 -- same value as the fake bid
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
  -- >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA after locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA after locking: " <> show ada

  -----------------------------------------------------------------------------
  -- Place a Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = fromInteger $ C.unCoin 10_000_000
          }
      bidRedeemer = NewBid firstBid
      bidDatum = AuctionDatum (Just firstBid)

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      bidNewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let bidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Refund the fake bidder exactly the fake bid amount
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId fakeBidder) (C.lovelaceToValue 5_000_000)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 1) -- Script output from first bid
  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA after bidding: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA after bidding: " <> show ada

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 10_000_000)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) nftOnly
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Seller Wallet ADA on the end: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Bidder Wallet ADA on the end: " <> show ada

  return ()

-- | SAA-0004: The AuctionDatum provided on deplyment is created with extra fields, then try to bid
extraFieldOnDatumBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => Int
  -> m ()
extraFieldOnDatumBidTest n = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  let extraFields = replicate n (BI.mkI 42)

  -- Initial datum: no bids yet, but injects some extra fields on BuiltinData level
  let malformedDatum = BI.mkConstr 0 (PlutusTx.toBuiltinData (Nothing :: Maybe Bid) : extraFields)

  let initialValue = BuildTx.assetValue policyId an 1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash malformedDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 10_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 10_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  -- Create a transaction to place the bid
  let bidTx =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  return ()

-- SAA-0004: The AuctionDatum provided on deplyment is created with extra fields, then try to payout
extraFieldOnDatumPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => Int
  -> m ()
extraFieldOnDatumPayoutTest n = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  let extraFields = replicate n (BI.mkI 42)

  -- Initial datum: no bids yet, but injects some extra fields on BuiltinData level
  let malformedDatum = BI.mkConstr 0 (PlutusTx.toBuiltinData (Nothing :: Maybe Bid) : extraFields)

  let initialValue = BuildTx.assetValue policyId an 1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash malformedDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- Payout after auction end
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- No bid - asset back to seller
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

{- | SAA-0005: Try to place a bid with a reference script that exceeds the maximum allowed size
  Case 1: The transaction is happenning normally (don't lock forever)
  Case 2: UTxO can be spent with higher taxes
-}
addReferenceScriptBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
addReferenceScriptBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before MintTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before MintTx: " <> show ada

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After MintTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After MintTx: " <> show ada

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  -- let validatorScript = auctionValidatorScript params :: C.PlutusScript C.PlutusScriptV3
  --     validator = C.PlutusScript C.plutusScriptVersion validatorScript :: C.Script C.PlutusScriptV3
  --     scriptHash = C.hashScript validator

  let hugeScript = hugeValidatorScript params :: C.PlutusScript C.PlutusScriptV3
      hugeValidator = C.PlutusScript C.plutusScriptVersion hugeScript
      hugeScriptHash = C.hashScript hugeValidator

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before Locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before Locking: " <> show ada

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatumWithRef Defaults.networkId hugeScriptHash initialDatum C.NoStakeAddress initialValue hugeValidator
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  -- let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  let refScriptTxIn = C.TxIn txId (C.TxIx 0)
  let txIn = C.TxIn txId (C.TxIx 1) -- the actual script UTxO is now at index 1
  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After Locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After Locking: " <> show ada

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 50_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 50_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before BidTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before BidTx: " <> show ada

  -- Create a transaction to place the bid
  let bidTx =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusRefWithInlineDatum refScriptTxIn txIn (C.plutusScriptVersion @C.PlutusScriptV3) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatumWithRef Defaults.networkId hugeScriptHash newDatum C.NoStakeAddress newValue hugeValidator

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After BidTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After BidTx: " <> show ada

  return ()

{- | SAA-0005: Try to place a bid and payout with a reference script that exceeds the maximum allowed size
  Case 1: The transaction is happenning normally (don't lock forever)
  Case 2: UTxO can be spent with higher taxes
-}
addReferenceScriptPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
addReferenceScriptPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  let hugeScript = hugeValidatorScript params :: C.PlutusScript C.PlutusScriptV3
      hugeValidator = C.PlutusScript C.plutusScriptVersion hugeScript
      hugeScriptHash = C.hashScript hugeValidator

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before createRefTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before createRefTx: " <> show ada

  let createRefTx =
        execBuildTx $
          BuildTx.createRefScriptNoDatum (MockWallet.addressInEra Defaults.networkId MockWallet.w1) hugeValidator (C.lovelaceToValue 30_000_000)

  refTxId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 createRefTx TrailingChange []

  mapM_
    ( \i -> do
        u <- singleUTxO (C.TxIn refTxId (C.TxIx i))
        logDebug $ "refTxId ix " <> show i <> ": " <> show u
    )
    [0, 1, 2]

  let refScriptTxIn = C.TxIn refTxId (C.TxIx 0)

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After createRefTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After createRefTx: " <> show ada

  logDebugS "---------------------------------------------------------------------"

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before MintTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before MintTx: " <> show ada

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After MintTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After MintTx: " <> show ada

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = BuildTx.assetValue policyId an 1

  -- let validatorScript = auctionValidatorScript params :: C.PlutusScript C.PlutusScriptV3
  --     validator = C.PlutusScript C.plutusScriptVersion validatorScript :: C.Script C.PlutusScriptV3
  --     scriptHash = C.hashScript validator

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before Locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before Locking: " <> show ada

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId hugeScriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []

  mapM_
    ( \i -> do
        u <- singleUTxO (C.TxIn txId (C.TxIx i))
        logDebug $ "lockTx ix " <> show i <> ": " <> show u
    )
    [0, 1, 2]

  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0)

  logDebug $ "refScriptTxIn: " <> show refScriptTxIn
  logDebug $ "txIn: " <> show txIn

  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After Locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After Locking: " <> show ada

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 50_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 50_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before BidTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before BidTx: " <> show ada

  -- Create a transaction to place the bid
  let bidTx =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusRefWithInlineDatum refScriptTxIn txIn (C.plutusScriptVersion @C.PlutusScriptV3) bidRedeemer
          -- BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          -- BuildTx.payToScriptInlineDatumWithRef Defaults.networkId hugeScriptHash newDatum C.NoStakeAddress newValue hugeValidator
          BuildTx.payToScriptInlineDatum Defaults.networkId hugeScriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  mapM_
    ( \i -> do
        u <- singleUTxO (C.TxIn txId2 (C.TxIx i))
        logDebug $ "bidTx ix " <> show i <> ": " <> show u
    )
    [0, 1]

  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid
  utxo2 <- singleUTxO txIn2
  let bidUtxoValue = case utxo2 of
        Nothing -> error "UTxO not found for bid output"
        Just txOut -> getTxOutValue txOut
      -- The bid UTxO holds NFT + 50 ADA. Seller gets the 50 ADA bid, bidder gets the rest (NFT + min ADA)
      nftAndMinAda = bidUtxoValue <> C.negateValue (C.lovelaceToValue 50_000_000)

  logDebug $ "lockedNftValue: " <> show lockedNftValue
  logDebug $ "bidUtxoValue: " <> show bidUtxoValue
  logDebug $ "nftAndMinAda: " <> show nftAndMinAda

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After BidTx: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After BidTx: " <> show ada

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA Before Payout: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA Before Payout: " <> show ada

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusRefWithInlineDatum refScriptTxIn txIn2 (C.plutusScriptVersion @C.PlutusScriptV3) payoutRedeemer
          -- BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          -- BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller)
          --                   (C.lovelaceToValue 50_000_000)
          -- Pay the NFT to the highest bidder
          -- BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) nftPayout
          -- Pay entire script UTxO value (NFT + min ADA) to the bidder
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 50_000_000)
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA After Payout: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA After Payout: " <> show ada

  return ()

-- | SAA-0006: Try to bid when auctioned token is not present at the produced utxo upon deployment
tokenNotPresentBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
tokenNotPresentBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = C.lovelaceToValue 2_000_000 -- Only ADA, no NFT
  -- BuildTx.assetValue policyId an 1
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 10_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 10_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  -- Create a transaction to place the bid
  let bidTx =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  return ()

-- | SAA-0006: Try to payout when auctioned token is not present at the produced utxo upon deployment
tokenNotPresentPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
tokenNotPresentPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = C.lovelaceToValue 2_000_000 -- Only ADA, no NFT
  -- BuildTx.assetValue policyId an 1
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1
  -- nftOnly = BuildTx.assetValue policyId an 1

  void $ MockWallet.w4 `paymentTo` MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- No bid - asset back to seller (but token is not present, so just ADA)
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 2_000_000)

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-- | SAA-0006: Try to payout when auctioned token is not present at the produced utxo upon deployment
tokenDoNotExistPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
tokenDoNotExistPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  -- let an = unTransAssetName (apTokenName params)

  -- Don't create the NFT in the seller wallet, just proceed to lock an empty UTxO with the auction script
  -- Create NFT in seller wallet (@TODO: create a minting policy)
  -- let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  -- _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = C.lovelaceToValue 2_000_000 -- Only ADA, no NFT
  -- BuildTx.assetValue policyId an 1
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1
  -- nftOnly = BuildTx.assetValue policyId an 1

  void $ MockWallet.w4 `paymentTo` seller -- Make sure seller has enough ADA's only to cover collateral
  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- No bid - asset back to seller (but token is not present, so just ADA)
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 2_000_000)

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-- | SAA-0007: Other tokens are present at the produced utxo upon deployment
otherTokensTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
otherTokensTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)
      ot1 = C.UnsafeAssetName "Other Token 1"
      ot2 = C.UnsafeAssetName "Other Token 2"

  -- Mint NFT + other tokens
  let mintTx = execBuildTx $ do
        BuildTx.mintPlutus mintingScript () an 1
        BuildTx.mintPlutus mintingScript () ot1 10
        BuildTx.mintPlutus mintingScript () ot2 20

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue =
        BuildTx.assetValue policyId an 1
          <> BuildTx.assetValue policyId ot1 10
          <> BuildTx.assetValue policyId ot2 20

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  utxo <- singleUTxO txIn1
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Place a Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = fromInteger $ C.unCoin 10_000_000
          }
      bidRedeemer = NewBid firstBid
      bidDatum = AuctionDatum (Just firstBid)

  -- New value = NFT + other tokens + first bid amount
  let oldAda = C.selectLovelace lockedNftValue
      tokensOnly = lockedNftValue <> C.negateValue (C.lovelaceToValue oldAda)
      -- We expect the new value to have the same other tokens + the new bid amount
      -- If the other tokens are not preserved, it means the contract is not handling them correctly
      bidNewValue = tokensOnly <> C.lovelaceToValue 10_000_000

  let bidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bidRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 10_000_000)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-- | SAA-0008: Upon deployment, there is more ada at the produced utxo than then minimum bid value
moreAdaThanMinBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
moreAdaThanMinBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA on the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Mint NFT
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue =
        BuildTx.assetValue policyId an 1
          <> C.lovelaceToValue 15_000_000 -- More ADA than the minimum bid value
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
  -- >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after locking: " <> show ada

  -----------------------------------------------------------------------------
  -- Place a Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = fromInteger $ C.unCoin 10_000_000
          }
      bidRedeemer = NewBid firstBid
      bidDatum = AuctionDatum (Just firstBid)

      -- New value = NFT + first bid amount (exactly the minimum)
      nftOnly = BuildTx.assetValue policyId an 1

  let bidNewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let bidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bidRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid
  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after bidding: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after bidding: " <> show ada

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 10_000_000)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) nftOnly
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA on the end: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA on the end: " <> show ada

  return ()

-- | SAA-0009: Uppon deployment, ada at produced utxo is high, but less than apMinBid, and bidder provides only the difference, then try another bid
firstBidUnderpaymentBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
firstBidUnderpaymentBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA on the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)
  let nftOnly = BuildTx.assetValue policyId an 1

  -- Mint NFT + other tokens
  let mintTx = execBuildTx $ do
        BuildTx.mintPlutus mintingScript () an 1

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue = nftOnly <> C.lovelaceToValue 8_000_000 -- A high value locked in the script, but less than apMinBid
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after locking: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after locking: " <> show ada

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = fromInteger $ C.unCoin 10_000_000
          }
      bid1Redeemer = NewBid firstBid
      bid1Datum = AuctionDatum (Just firstBid)

  -- NFT + Bid Value (only 10 adas)
  let bid1NewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let bid1Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bid1Redeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid1Datum C.NoStakeAddress bid1NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bid1Tx TrailingChange []
  -- let txIn1 = C.TxIn txId1 (C.TxIx 0)  -- Script output from first bid
  txIn1 <- fst . head <$> utxosAt scriptHash

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after first bid: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after first bid: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after first bid: " <> show ada

  -----------------------------------------------------------------------------
  -- Place second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2

  let bidder2 = MockWallet.w3
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin 15_000_000
          }
      bid2Redeemer = NewBid secondBid
      bid2Datum = AuctionDatum (Just secondBid)

  let bid2NewValue = nftOnly <> C.lovelaceToValue 15_000_000 -- The script will have NFT + Bid 2
  let bid1RefundValue = C.lovelaceToValue 10_000_000

  let bid2Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bid2Redeemer
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) bid1RefundValue
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid2Datum C.NoStakeAddress bid2NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder2 bid2Tx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after second bid: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after second bid: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after second bid: " <> show ada

  return ()

-- | SAA-0009: Uppon deployment, ada at produced utxo is high, but less than apMinBid, and bidder provides only the difference, then payout
firstBidUnderpaymentPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
firstBidUnderpaymentPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA on the beginning: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA on the beginning: " <> show ada

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)
  let nftOnly = BuildTx.assetValue policyId an 1

  -- Mint NFT
  let mintTx = execBuildTx $ do
        BuildTx.mintPlutus mintingScript () an 1

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue = nftOnly <> C.lovelaceToValue 8_000_000

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after locking: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after locking: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after locking: " <> show ada

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = fromInteger $ C.unCoin 10_000_000
          }
      bid1Redeemer = NewBid firstBid
      bid1Datum = AuctionDatum (Just firstBid)

  -- NFT + Bid Value
  let bid1NewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let bid1Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bid1Redeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid1Datum C.NoStakeAddress bid1NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bid1Tx TrailingChange []
  -- let txIn1 = C.TxIn txId1 (C.TxIx 0)  -- Script output from first bid
  txIn1 <- fst . head <$> utxosAt scriptHash

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after first bid: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after first bid: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after first bid: " <> show ada

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  let sellerPayoutValue = C.lovelaceToValue 10_000_000 -- Seller should receive locked value, but not the NFT
  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  -- void $ MockWallet.w4 `paymentTo` bidder2

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) sellerPayoutValue
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) nftOnly
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  getWalletAda MockWallet.w1 >>= \ada -> logDebug $ "Wallet 1 ADA after payout: " <> show ada
  getWalletAda MockWallet.w2 >>= \ada -> logDebug $ "Wallet 2 ADA after payout: " <> show ada
  getWalletAda MockWallet.w3 >>= \ada -> logDebug $ "Wallet 3 ADA after payout: " <> show ada

  return ()

-- | SAA-0010: Try to bid when the current slot is past the auction end time
endTimeBeforeBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.SlotNo
  -> m ()
endTimeBeforeBidTest slot = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -- Create a bid with the specified value
  let bidder = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = 10_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 10_000_000

  -- Set the slot to a time before auction end
  setSlot slot

  -- Create a transaction to place the bid
  let bidTx =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots slot (slot + 1)
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  return ()

-- | SAA-0010: Payout when auction end time doesn't allow any bid (should allow)
payoutWithNoBidsTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
payoutWithNoBidsTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue =
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 30

  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 30 32
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
          -- Payout with no bid - asset back to seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-- | SAA-0011: Uppon bidding, address exceeds 32 bytes, and tries to place another bid
wrongAddressBidTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrongAddressBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = BuildTx.assetValue policyId an 1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2) and simulate large datum attack
  -----------------------------------------------------------------------------

  -- Create a bid with the specified value
  let bidder1 = MockWallet.w2
      bidderAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
      bidderAddrAttack = foldl PlutusTx.appendByteString PlutusTx.emptyByteString (replicate 154 bidderAddr)

  let firstBid =
        Bid
          { bAddr = bidderAddrAttack <> "XXXXXXXXXXXXXX" -- Use the attack address that exceeds 32 bytes
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = 30_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 30_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  -- Create a transaction to place the bid
  let bidTx1 =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bidTx1 TrailingChange []
  txIn1 <- fst . head <$> utxosAt scriptHash

  -----------------------------------------------------------------------------
  -- Place second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2

  let bidder2 = MockWallet.w3
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin 50_000_000
          }
      bid2Redeemer = NewBid secondBid
      bid2Datum = AuctionDatum (Just secondBid)

  let bid2NewValue = nftOnly <> C.lovelaceToValue 50_000_000 -- The script will have NFT + Bid 2
  let bid1RefundValue = C.lovelaceToValue 30_000_000

  let bid2Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bid2Redeemer
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) bid1RefundValue -- Refund the first bidder
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid2Datum C.NoStakeAddress bid2NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder2 bid2Tx TrailingChange []

  return ()

-- | SAA-0011: Uppon bidding, address exceeds 32 bytes, and tries to payout
wrongAddressPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrongAddressPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000 -- 10 ADA minimum
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)

  -- Create NFT in seller wallet (@TODO: create a minting policy)
  let mintTx = execBuildTx (BuildTx.mintPlutus mintingScript () an 1)

  -- Submit mint transaction from wallet 1 (the seller)
  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Initial datum: no bids yet
  let initialDatum = AuctionDatum Nothing
  let initialValue = BuildTx.assetValue policyId an 1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Lock the NFT in the auction script
  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit lock transaction from wallet 1 (the seller)
  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  -- Get the TxIn of the locked UTxO
  let txIn = C.TxIn txId (C.TxIx 0) -- Assuming the locked UTxO is at index 0 of the transaction outputs, adjust if necessary
  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of -- lockedNftValue + minAda
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2) and simulate large datum attack
  -----------------------------------------------------------------------------

  -- Create a bid with the specified value
  let bidder1 = MockWallet.w2
      bidderAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
      bidderAddrAttack = foldl PlutusTx.appendByteString PlutusTx.emptyByteString (replicate 154 bidderAddr)

  let firstBid =
        Bid
          { bAddr = bidderAddrAttack <> "XXXXXXXXXXXXXX" -- Use the attack address that exceeds 32 bytes
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = 30_000_000
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue 30_000_000

  -- Set the slot to a time before auction end
  setSlot 0

  -- Create a transaction to place the bid
  let bidTx1 =
        execBuildTx $ do
          -- Set a validity range before auction end time
          BuildTx.addValidityRangeSlots 0 2
          -- Spend the script UTxO with redeemer
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
          -- Recreate script UTxO with updated datum and value
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bidTx1 TrailingChange []
  txIn1 <- fst . head <$> utxosAt scriptHash

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- Payout after auction end
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) (C.lovelaceToValue 30_000_000)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-- | SAA-0012: Uppon bidding, the new utxo is flooded with additional tokens, and then try another bid
additionalTokensOnBidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
additionalTokensOnBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)
  let nftOnly = BuildTx.assetValue policyId an 1

  -- Mint NFT + other tokens
  let mintTx = execBuildTx $ do
        BuildTx.mintPlutus mintingScript () an 1

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue = nftOnly

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of -- lockedNftValue + minAda
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = fromInteger $ C.unCoin 30_000_000
          }
      bid1Redeemer = NewBid firstBid
      bid1Datum = AuctionDatum (Just firstBid)

  -- Generate MANY garbage token names under same policy
  let garbageTokenNames =
        fmap
          (\i -> C.UnsafeAssetName (pack $ "A" <> show i))
          ([1 .. 181] :: [Int]) -- budget limit (had to change Defaults to reach this limit)

  -- Mint all garbage tokens
  let mintGarbageTx =
        execBuildTx $ do
          forM_ garbageTokenNames $ \tn ->
            BuildTx.mintPlutus mintingScript () tn 1

  _ <- tryBalanceAndSubmit mempty bidder1 mintGarbageTx TrailingChange []

  -- Build flood value (all under SAME policyId)
  let garbageValue =
        mconcat $
          fmap
            (\tn -> BuildTx.assetValue policyId tn 1)
            garbageTokenNames

  -- New value = NFT + first bid amount
  let oldAda = C.selectLovelace lockedNftValue
      tokensOnly = lockedNftValue <> C.negateValue (C.lovelaceToValue oldAda) -- Same as nftOnly

  -- Garbage value + Locked Tokens + Bid Value
  let bid1NewValue =
        garbageValue
          <> tokensOnly
          <> C.lovelaceToValue 30_000_000

  void $ MockWallet.w4 `paymentTo` bidder1 -- sending some ada only for colateral
  let bid1Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bid1Redeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid1Datum C.NoStakeAddress bid1NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bid1Tx TrailingChange []
  -- let txIn1 = C.TxIn txId1 (C.TxIx 0)  -- Script output from first bid
  txIn1 <- fst . head <$> utxosAt scriptHash

  -----------------------------------------------------------------------------
  -- Place second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2

  let bidder2 = MockWallet.w3
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin 50_000_000
          }
      bid2Redeemer = NewBid secondBid
      bid2Datum = AuctionDatum (Just secondBid)

  let bid2NewValue = garbageValue <> nftOnly <> C.lovelaceToValue 50_000_000 -- The script will have NFT + Bid 2
  let bid1RefundValue = C.lovelaceToValue 30_000_000 -- scriptLockedValue1 <> C.negateValue nftOnly -- refunds everything, except NFT

  -- let bid2NewValue = nftOnly <> C.lovelaceToValue 50_000_000 -- The script will have NFT + Bid 2
  -- let bid1RefundValue = garbageValue <> C.lovelaceToValue 30_000_000 -- refunds everything, except NFT

  let bid2Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bid2Redeemer
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) bid1RefundValue
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid2Datum C.NoStakeAddress bid2NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder2 bid2Tx TrailingChange []

  return ()

-- | SAA-0012: Uppon bidding, the new utxo is flooded with additional tokens, and then try to payout
additionalTokensOnBidPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadLog m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
additionalTokensOnBidPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters
  let params =
        AuctionParams
          { apSeller = transPubKeyHash $ verificationKeyHash MockWallet.w1
          , apCurrencySymbol = cs
          , apTokenName = tokenName "NFT"
          , apMinBid = 10_000_000
          , apEndTime = POSIXTime 1640995220000 -- Slot 20
          }

  let an = unTransAssetName (apTokenName params)
  let nftOnly = BuildTx.assetValue policyId an 1

  -- Mint NFT + other tokens
  let mintTx = execBuildTx $ do
        BuildTx.mintPlutus mintingScript () an 1

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 mintTx TrailingChange []

  -- Lock NFT in script
  let initialDatum = AuctionDatum Nothing
  let initialValue = nftOnly

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn = C.TxIn txId (C.TxIx 0)

  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of -- lockedNftValue + minAda
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  -----------------------------------------------------------------------------
  -- Place first Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = fromInteger $ C.unCoin 30_000_000
          }
      bid1Redeemer = NewBid firstBid
      bid1Datum = AuctionDatum (Just firstBid)

  -- Generate MANY garbage token names under same policy
  let garbageTokenNames =
        fmap
          (\i -> C.UnsafeAssetName (pack $ "A" <> show i))
          ([1 .. 181] :: [Int]) -- budget limit (had to change Defaults to reach this limit)

  -- Mint all garbage tokens
  let mintGarbageTx =
        execBuildTx $ do
          forM_ garbageTokenNames $ \tn ->
            BuildTx.mintPlutus mintingScript () tn 1

  _ <- tryBalanceAndSubmit mempty bidder1 mintGarbageTx TrailingChange []

  -- Build flood value (all under SAME policyId)
  let garbageValue =
        mconcat $
          fmap
            (\tn -> BuildTx.assetValue policyId tn 1)
            garbageTokenNames

  -- New value = NFT + first bid amount
  let oldAda = C.selectLovelace lockedNftValue
      tokensOnly = lockedNftValue <> C.negateValue (C.lovelaceToValue oldAda) -- Same as nftOnly

  -- Garbage value + Locked Tokens + Bid Value
  let bid1NewValue =
        garbageValue
          <> tokensOnly
          <> C.lovelaceToValue 30_000_000

  void $ MockWallet.w4 `paymentTo` bidder1 -- sending some ada only for colateral
  let bid1Tx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bid1Redeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bid1Datum C.NoStakeAddress bid1NewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 bid1Tx TrailingChange []
  -- let txIn1 = C.TxIn txId1 (C.TxIx 0)  -- Script output from first bid
  txIn1 <- fst . head <$> utxosAt scriptHash

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  let sellerPayoutValue = garbageValue <> C.lovelaceToValue 30_000_000 -- Seller should receive locked value, but not the NFT
  setSlot 20 -- end of the auction
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  -- void $ MockWallet.w4 `paymentTo` bidder2

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) sellerPayoutValue
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()
