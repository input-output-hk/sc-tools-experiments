{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Auction.Spec.Unit where

import Auction.Scripts (auctionValidatorScript)
import Auction.Utils (getTxOutValue, mintingScript, utxosAt)
import Auction.Validator (AuctionDatum (AuctionDatum), AuctionParams (..), AuctionRedeemer (..), Bid (Bid, bAddr, bAmount, bPkh))
import Cardano.Api qualified as C
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot, singleUTxO)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash, unTransAssetName)
import Convex.Utils (failOnError)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import PlutusLedgerApi.Common qualified as PlutusTx
import PlutusLedgerApi.V1 (CurrencySymbol (..), POSIXTime (..), tokenName)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)

-------------------------------------------------------------------------------
-- Unit tests for the Auction script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ testCase
        "First bid equals minimum bid"
        (mockchainSucceeds $ failOnError $ firstBidTest 10_000_000)
    , testCase
        "First bid exceeds minimum bid"
        (mockchainSucceeds $ failOnError $ firstBidTest 15_000_000)
    , testCase
        "Fail: First bid below minimum bid"
        (mockchainFails (failOnError (firstBidTest 5_000_000)) (\_ -> pure ()))
    , testCase
        "Second bid higher than current highest"
        (mockchainSucceeds $ failOnError $ secondBidTest 10_000_000 15_000_000)
    , testCase
        "Fail: Second bid equal to current highest"
        (mockchainFails (failOnError (secondBidTest 15_000_000 15_000_000)) (\_ -> pure ()))
    , testCase
        "Fail: Second bid equal to current highest"
        (mockchainFails (failOnError (secondBidTest 20_000_000 15_000_000)) (\_ -> pure ()))
    , testCase
        "Bid placed before end time"
        (mockchainSucceeds $ failOnError $ bidTimeTest 10)
    , testCase
        "Bid placed exactly at end time"
        (mockchainSucceeds $ failOnError $ bidTimeTest 19)
    , testCase
        "Fail: Bid placed after end time"
        (mockchainFails (failOnError (bidTimeTest 25)) (\_ -> pure ()))
    , testCase
        "Fail: Transaction validity range extends beyond end time"
        (mockchainFails (failOnError (bidTimeTest 20)) (\_ -> pure ()))
    , testCase
        "Previous bidder receives exact refund amount"
        (mockchainSucceeds $ failOnError $ refundsBidTest 10_000_000 MockWallet.w2)
    , testCase
        "Fail: Previous bidder receives partial refund"
        (mockchainFails (failOnError (refundsBidTest 8_000_000 MockWallet.w2)) (\_ -> pure ()))
    , testCase
        "Fail: Previous bidder receives excess refund"
        (mockchainFails (failOnError (refundsBidTest 12_000_000 MockWallet.w2)) (\_ -> pure ()))
    , testCase
        "Fail: Refund sent to wrong address"
        (mockchainFails (failOnError (refundsBidTest 12_000_000 MockWallet.w4)) (\_ -> pure ()))
    , testCase
        "Fail: No refund output when previous bid exists"
        (mockchainFails (failOnError noRefundsBidTest) (\_ -> pure ()))
    , testCase
        "Payout after end time and  Seller receives exact highest bid amount"
        (mockchainSucceeds $ failOnError $ validPayoutTimeTest 21 10_000_000)
    , testCase
        "Payout exactly at end time"
        (mockchainSucceeds $ failOnError $ validPayoutTimeTest 20 10_000_000)
    , testCase
        "Fail: Payout before end time"
        (mockchainFails (failOnError (validPayoutTimeTest 15 10_000_000)) (\_ -> pure ()))
    , testCase
        "Fail: Transaction validity range starts before end time"
        (mockchainFails (failOnError (validPayoutTimeTest 19 10_000_000)) (\_ -> pure ()))
    , testCase
        "No bids - seller gets nothing"
        (mockchainSucceeds $ failOnError noBidPayoutTest)
    , testCase
        "Fail: Seller receives less than highest bid"
        (mockchainFails (failOnError (validPayoutTimeTest 21 8_000_000)) (\_ -> pure ()))
    , testCase
        "Fail: Seller receives more than highest bid"
        (mockchainFails (failOnError (validPayoutTimeTest 21 12_000_000)) (\_ -> pure ()))
    , testCase
        "Fail: Payment sent to wrong seller address"
        (mockchainFails (failOnError (paymentToWrongAddressTest MockWallet.w3 MockWallet.w2)) (\_ -> pure ()))
    , testCase
        "Fail: No payment output when bid exists"
        (mockchainFails (failOnError noPaymentOutputTest) (\_ -> pure ()))
    , testCase
        "No bids - seller receives asset back"
        (mockchainSucceeds $ failOnError noBidPayToSellerTest)
    , testCase
        "Fail: Asset sent to wrong bidder address"
        (mockchainFails (failOnError (paymentToWrongAddressTest MockWallet.w1 MockWallet.w4)) (\_ -> pure ()))
    , testCase
        "Fail: Asset not included in any output"
        (mockchainFails (failOnError assetNotIncludedOutputTest) (\_ -> pure ()))
    , testCase
        "Fail: Wrong token sent to bidder"
        (mockchainFails (failOnError wrongTokenSentToBidderTest) (\_ -> pure ()))
    , testCase
        "Fail: Wrong amount of tokens (not exactly 1)"
        (mockchainFails (failOnError wrongAmountOfTokensTest) (\_ -> pure ()))
    ]

-- ============================================================================
-- NewBid Redeemer Tests
-- ============================================================================

-------------------------------------------------------------------------------
-- Sufficient Bid Validation Tests
-------------------------------------------------------------------------------

firstBidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace
  -> m ()
firstBidTest value = do
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
          , bAmount = fromInteger $ C.unCoin value
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      -- New value = NFT + bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      newValue = nftOnly <> C.lovelaceToValue value

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

secondBidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace -- First bid amount
  -> C.Lovelace -- Second bid amount
  -> m ()
secondBidTest firstBidValue secondBidValue = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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
  -- First Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = fromInteger $ C.unCoin firstBidValue
          }
      firstRedeemer = NewBid firstBid
      firstDatum = AuctionDatum (Just firstBid)

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      firstNewValue = nftOnly <> C.lovelaceToValue firstBidValue

  let firstBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) firstRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash firstDatum C.NoStakeAddress firstNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 firstBidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2 -- Still before auction end (slot 20)
  let bidder2 = MockWallet.w3 -- Different bidder
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin secondBidValue
          }
      secondRedeemer = NewBid secondBid
      secondDatum = AuctionDatum (Just secondBid)
      -- New value = NFT + second bid amount
      secondNewValue = nftOnly <> C.lovelaceToValue secondBidValue

  let secondBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          -- Spend the script UTxO (contains first bid + NFT)
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) secondRedeemer
          -- Refund the first bidder exactly their bid amount
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) (C.lovelaceToValue firstBidValue)
          -- Pay to script with new datum and value (second bid + NFT)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash secondDatum C.NoStakeAddress secondNewValue

  _ <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder2 secondBidTx TrailingChange []
  -- let txIn3 = C.TxIn txId3 (C.TxIx 1)  -- Script output from first bid

  txIn3 <- fst . head <$> utxosAt scriptHash

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20 -- Payout according to parameter
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn3 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue secondBidValue)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder2) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-----------------------------------------------------------------------------
-- Valid Bid Timing Tests
-----------------------------------------------------------------------------

bidTimeTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.SlotNo
  -> m ()
bidTimeTest slot = do
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

-----------------------------------------------------------------------------
-- Refunds Previous Highest Bid Tests
-----------------------------------------------------------------------------

refundsBidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.Lovelace
  -- ^ Amount to be refunded to the bidder
  -> Wallet
  -- ^ Wallet to receive refunds
  -> m ()
refundsBidTest value w = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -----------------------------------------------------------------------------
  -- First Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = 10_000_000
          }
      firstRedeemer = NewBid firstBid
      firstDatum = AuctionDatum (Just firstBid)

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      firstNewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let firstBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) firstRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash firstDatum C.NoStakeAddress firstNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 firstBidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2 -- Still before auction end (slot 20)
  let bidder2 = MockWallet.w3 -- Different bidder
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin 20_000_000
          }
      secondRedeemer = NewBid secondBid
      secondDatum = AuctionDatum (Just secondBid)
      -- New value = NFT + second bid amount
      secondNewValue = nftOnly <> C.lovelaceToValue 20_000_000

  let secondBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          -- Spend the script UTxO (contains first bid + NFT)
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) secondRedeemer
          -- Refund the first bidder the value received as parameter
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId w) (C.lovelaceToValue value)
          -- Pay to script with new datum and value (second bid + NFT)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash secondDatum C.NoStakeAddress secondNewValue

  _ <- tryBalanceAndSubmit mempty bidder2 secondBidTx TrailingChange []

  return ()

noRefundsBidTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noRefundsBidTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -----------------------------------------------------------------------------
  -- First Bid (from wallet 2)
  -----------------------------------------------------------------------------

  setSlot 0

  let bidder1 = MockWallet.w2
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder1
          , bPkh = transPubKeyHash $ verificationKeyHash bidder1
          , bAmount = 10_000_000
          }
      firstRedeemer = NewBid firstBid
      firstDatum = AuctionDatum (Just firstBid)

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      firstNewValue = nftOnly <> C.lovelaceToValue 10_000_000

  let firstBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 0 2
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) firstRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash firstDatum C.NoStakeAddress firstNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder1 firstBidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Second Bid (from wallet 3)
  -----------------------------------------------------------------------------

  setSlot 2 -- Still before auction end (slot 20)
  let bidder2 = MockWallet.w3 -- Different bidder
      secondBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder2
          , bPkh = transPubKeyHash $ verificationKeyHash bidder2
          , bAmount = fromInteger $ C.unCoin 20_000_000
          }
      secondRedeemer = NewBid secondBid
      secondDatum = AuctionDatum (Just secondBid)
      -- New value = NFT + second bid amount
      secondNewValue = nftOnly <> C.lovelaceToValue 20_000_000

  let secondBidTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 2 4
          -- Spend the script UTxO (contains first bid + NFT)
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) secondRedeemer
          -- Don't refund the first bidder to test the contract's behavior when no refund is provided
          -- BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder1) (C.lovelaceToValue 10_000_000)
          -- Pay to script with new datum and value (second bid + NFT)
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash secondDatum C.NoStakeAddress secondNewValue

  _ <- tryBalanceAndSubmit mempty bidder2 secondBidTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Correct Output Tests
-------------------------------------------------------------------------------

-- ============================================================================
-- Payout Redeemer Tests
-- ============================================================================

-------------------------------------------------------------------------------
-- Valid Payout Time Tests
-------------------------------------------------------------------------------

validPayoutTimeTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => C.SlotNo
  -> C.Lovelace
  -> m ()
validPayoutTimeTest slot value = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      bidNewValue = nftOnly <> C.lovelaceToValue 10_000_000

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

  setSlot slot -- Payout according to parameter
  let payoutRedeemer = Payout
      seller = MockWallet.w1

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots slot (slot + 2)
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue value)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Seller Gets Highest Bid Tests
-------------------------------------------------------------------------------

noBidPayoutTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noBidPayoutTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

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

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

paymentToWrongAddressTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => Wallet
  -- ^ Seller wallet to receive the bid amount
  -> Wallet
  -- ^ Bidder wallet to receive the NFT
  -> m ()
paymentToWrongAddressTest testSeller testBidder = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      bidNewValue = nftOnly <> C.lovelaceToValue 10_000_000

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

  setSlot 20

  let payoutRedeemer = Payout

  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId testSeller)
            (C.lovelaceToValue 10_000_000)
          -- Pay the NFT to the bidder passed as parameter
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId testBidder) lockedNftValue

  _ <- tryBalanceAndSubmit mempty testSeller payoutTx TrailingChange []

  return ()

noPaymentOutputTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noPaymentOutputTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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

      -- New value = NFT + first bid amount
      nftOnly = BuildTx.assetValue policyId an 1
      bidNewValue = nftOnly <> C.lovelaceToValue 10_000_000

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

  setSlot 20

  let payoutRedeemer = Payout
      seller = MockWallet.w3 -- Incorrect seller address to test that the contract doesn't allow payment to the wrong address
  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          -- BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller)
          --                      (C.lovelaceToValue 10_000_000)
          -- Pay the NFT to the highest bidder
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

-------------------------------------------------------------------------------
-- Highest Bidder Gets Asset Tests
-------------------------------------------------------------------------------

noBidPayToSellerTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
noBidPayToSellerTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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
          -- Pay the NFT back to the seller since there were no bids
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId seller) lockedNftValue

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

assetNotIncludedOutputTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
assetNotIncludedOutputTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- utxo <- singleUTxO txIn1
  -- let lockedNftValue = case utxo of
  --       Nothing -> error "UTxO not found for payout"
  --       Just txOut -> getTxOutValue txOut

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
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bidRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20

  let payoutRedeemer = Payout
      seller = MockWallet.w3 -- Incorrect seller address to test that the contract doesn't allow payment to the wrong address
  let payoutTx =
        execBuildTx $ do
          BuildTx.addValidityRangeSlots 20 22
          -- Spend the script UTxO with Payout redeemer
          BuildTx.spendPlutusInlineDatum txIn2 (auctionValidatorScript params) payoutRedeemer
          -- Pay the bid amount to the seller
          BuildTx.payToAddress
            (MockWallet.addressInEra Defaults.networkId seller)
            (C.lovelaceToValue 10_000_000)
          -- Don't include the NFT in the payout to test that the contract doesn't allow payout if the asset is not included in the output
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) (C.lovelaceToValue 2_000_000) -- lockedNftValue
  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()

wrongTokenSentToBidderTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrongTokenSentToBidderTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  let lockTx =
        execBuildTx $
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash initialDatum C.NoStakeAddress initialValue
            >> BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  txId1 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []
  let txIn1 = C.TxIn txId1 (C.TxIx 0)

  -- Creating a fake token to send to the winner
  let lockedNftValue = BuildTx.assetValue policyId (C.UnsafeAssetName "Fake NFT") 1 <> C.lovelaceToValue 2_000_000

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
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bidRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20

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

wrongAmountOfTokensTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
wrongAmountOfTokensTest = do
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId

  -- Define auction parameters (same as firstBidTest)
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
        BuildTx.assetValue
          (C.hashScript $ C.PlutusScript C.plutusScriptVersion mintingScript)
          an
          1

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

  -- Sending 2 NFTs instead of 1 to the winner
  let wrongAmountOfTokens = lockedNftValue <> BuildTx.assetValue policyId an 1

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
          BuildTx.spendPlutusInlineDatum txIn1 (auctionValidatorScript params) bidRedeemer
          BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash bidDatum C.NoStakeAddress bidNewValue

  txId2 <- C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty bidder bidTx TrailingChange []
  let txIn2 = C.TxIn txId2 (C.TxIx 0) -- Script output from first bid

  -----------------------------------------------------------------------------
  -- Payout
  -----------------------------------------------------------------------------

  setSlot 20

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
          BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) wrongAmountOfTokens

  _ <- tryBalanceAndSubmit mempty seller payoutTx TrailingChange []

  return ()
