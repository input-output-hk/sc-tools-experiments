{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Auction.Spec.Prop (
  propBasedTests,
) where

import Auction.Scripts (auctionValidatorScript)
import Auction.Utils (getTxOutValue, mintingScript, utxosAt)
import Auction.Validator (AuctionDatum (AuctionDatum), AuctionParams (..), AuctionRedeemer (..), Bid (Bid, bAddr, bAmount, bPkh))
import Cardano.Api qualified as C
import Control.Monad (void, when)
import Control.Monad.Except (MonadError, runExceptT)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain, setSlot, singleUTxO)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash, unTransAssetName)
import Convex.TestingInterface (TestingInterface (..), ThreatModelsFor (..), propRunActions)
import Convex.ThreatModel.DoubleSatisfaction (doubleSatisfaction)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.ThreatModel.TokenForgery (simpleAlwaysSucceedsMintingPolicyV2, simpleTestAssetName, tokenForgeryAttack)
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Data.Foldable (for_)
import GHC.Generics (Generic)
import PlutusLedgerApi.Common qualified as PlutusTx
import PlutusLedgerApi.V1 (CurrencySymbol (..), tokenName)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck qualified as QC

-------------------------------------------------------------------------------
-- Property-based tests for the Auction contract
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ propRunActions @AuctionModel "Property-based test auction contract"
    ]

-------------------------------------------------------------------------------
-- Auction Testing Interface
-------------------------------------------------------------------------------

{- | Model of the Auction contract state for property-based testing.

  Configuration:
  - Seller: MockWallet.w1
  - Minimum bid: 10 ADA (10_000_000 lovelace)
  - Auction end: slot 100
  - Asset: 1 NFT with a specific currency symbol and token name
  - Start time: slot 0
-}
data AuctionModel = AuctionModel
  { _highestBidAmount :: C.Lovelace
  -- ^ The amount of the highest bid so far (0 if no bids)
  , _highestBidder :: Maybe Wallet
  -- ^ The wallet of the highest bidder (Nothing if no bids)
  , _curSlot :: C.SlotNo
  -- ^ The current slot
  , _seller :: Wallet
  -- ^ The seller (beneficiary receiving the highest bid)
  , _minBid :: C.Lovelace
  -- ^ The minimum bid amount
  , _endSlot :: C.SlotNo
  -- ^ The auction end time (in slots)
  , _auctionInitialized :: Bool
  -- ^ Whether the auction has been initialized with NFT lock
  , _auctionClosed :: Bool
  -- ^ Whether the auction has been closed (payout executed)
  , _policyId :: Maybe C.ScriptHash
  -- ^ The minting policy script hash
  , _scriptHash :: Maybe C.ScriptHash
  -- ^ The validator script hash
  , _auctionTxIn :: Maybe C.TxIn
  -- ^ The current auction UTxO reference
  }
  deriving (Show, Eq, Generic)

instance TestingInterface AuctionModel where
  data Action AuctionModel
    = PrepareAuction
    | -- \^ Initialize the auction by locking the NFT
      PlaceBid Wallet C.Lovelace
    | -- \^ Place a bid in the auction
      CloseAuction
    | -- \^ Close the auction and execute payout
      WaitSlots C.SlotNo
    -- \^ Advance blockchain time
    deriving (Show, Eq)

  -- \| Initial state for auction scenario.
  --
  --    Configuration:
  --    - Seller: MockWallet.w1
  --    - Minimum bid: 10 ADA (10_000_000 lovelace)
  --    - Auction end: slot 50
  --    - Start time: slot 0
  --    - No bids initially
  initialize =
    pure
      AuctionModel
        { _highestBidAmount = 0
        , _highestBidder = Nothing
        , _curSlot = 0
        , _seller = MockWallet.w1
        , _minBid = 10_000_000
        , _endSlot = 50
        , _auctionInitialized = False
        , _auctionClosed = False
        , _policyId = Nothing
        , _scriptHash = Nothing
        , _auctionTxIn = Nothing
        }

  -- \| Generate random actions weighted by likelihood and current state.
  arbitraryAction am =
    QC.frequency
      [ (prepareWeight, genPrepare)
      , (closeWeight, genClose)
      , (bidWeight, genBid)
      , (waitWeight, genWait)
      ]
   where
    -- Weights adjust based on state
    prepareWeight = if _auctionInitialized am then 0 else 10

    bidWeight
      | _auctionClosed am || not (_auctionInitialized am) = 0
      | _curSlot am >= _endSlot am = 2
      | otherwise = 5

    closeWeight
      | _auctionClosed am || not (_auctionInitialized am) = 0
      | _curSlot am >= _endSlot am = 10
      | otherwise = 1

    waitWeight = 3

    genPrepare = pure PrepareAuction

    genBid = do
      wallet <- QC.elements bidders
      -- Generate bid amounts: any amount >= 1 ADA
      let currentHighest = C.unCoin $ _highestBidAmount am
          minBidAmt = C.unCoin $ _minBid am
          baseBid = max minBidAmt (currentHighest + 1_000_000) -- at least 1 ADA higher
      bidAmt <- Gen.chooseInteger (baseBid, baseBid + 100_000_000) -- up to 100 ADA more
      pure $ PlaceBid wallet (C.Coin bidAmt)

    genClose = pure CloseAuction

    genWait = do
      -- Advance 1-30 slots
      slots <- C.SlotNo <$> Gen.chooseWord64 (1, 20)
      pure $ WaitSlots slots

  -- \| Preconditions determine which actions are valid in the current state.
  precondition am PrepareAuction =
    -- Can only prepare once
    not (_auctionInitialized am)
  precondition am (PlaceBid w amt) =
    -- Auction must be initialized
    _auctionInitialized am
      -- Cannot bid after auction is closed
      && not (_auctionClosed am)
      -- Cannot bid after deadline
      && _curSlot am < _endSlot am
      -- Bid must be at least the minimum bid (if no bids yet)
      && case _highestBidder am of
        Nothing -> amt >= _minBid am
        Just _ -> amt > _highestBidAmount am
      -- Seller cannot bid (although it is not enforced by the contract)
      && w /= _seller am
  precondition am CloseAuction =
    -- Auction must be initialized
    _auctionInitialized am
      -- Cannot close before the auction ends
      && _curSlot am >= _endSlot am
      -- Auction must not already be closed
      && not (_auctionClosed am)
  -- Time can always advance
  precondition _ (WaitSlots _) = True

  -- \| perform executes actions on the actual blockchain/mockchain.
  perform am PrepareAuction =
    do
      -- C.liftIO $ putStrLn $ ">>> Preparing auction (minting NFT and locking in script) at slot " ++ show (_curSlot am)
      let auctionParams = paramsFromModel am
      runExceptT $
        prepareAuctionPBT auctionParams
      >>= \case
        Left err -> fail $ "PrepareAuction failed: " <> show err
        Right _ ->
          pure $
            am
              { _auctionInitialized = True
              , _curSlot = _curSlot am + 1
              }
  perform am (PlaceBid w amt) =
    do
      -- C.liftIO $ putStrLn $ ">>> Placing bid of " ++ show amt ++ " lovelace from " ++ show w ++ " at slot " ++ show (_curSlot am)
      if not (_auctionInitialized am)
        then fail "Auction not initialized"
        else
          do
            let auctionParams = paramsFromModel am
            runExceptT $
              placeBidPBT auctionParams (_curSlot am) (_highestBidder am) (_highestBidAmount am) w amt
            >>= \case
              Left err -> fail $ "PlaceBid failed: " <> show err
              Right _ -> pure ()
      pure $
        am
          { _highestBidAmount = amt
          , _highestBidder = Just w
          , _curSlot = _curSlot am + 1 -- advancing time by 1 slot
          }
  perform am CloseAuction =
    do
      -- C.liftIO $ putStrLn $ ">>> Closing auction at slot " ++ show (_curSlot am)
      if not (_auctionInitialized am)
        then fail "Auction not initialized"
        else
          do
            let auctionParams = paramsFromModel am
            runExceptT $
              closeAuctionPBT auctionParams (_curSlot am) (_highestBidder am) (_highestBidAmount am)
            >>= \case
              Left err -> fail $ "CloseAuction failed: " <> show err
              Right _ -> pure ()
      pure $
        am
          { _auctionClosed = True
          , _curSlot = _curSlot am + 1 -- advancing time by 1 slot
          }
  perform am (WaitSlots slots) =
    do
      -- C.liftIO $ putStrLn $ ">>> Waiting " ++ show slots ++ " slots (now at " ++ show (_curSlot am + slots) ++ ")"
      pure $
        am
          { _curSlot = _curSlot am + slots
          }

  validate _am = pure True

  monitoring _ _ = error "monitoring not implemented"

instance ThreatModelsFor AuctionModel where
  threatModels = [doubleSatisfaction]
  expectedVulnerabilities = [timeBoundManipulation, tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName]

-- threatModels = [doubleSatisfaction, datumListBloatAttack, datumByteBloatAttack, duplicateListEntryAttack
--                , largeDataAttackWith 10, largeValueAttackWith 10, inputDuplication, mutualExclusionAttack
--                , negativeIntegerAttack, redeemerAssetSubstitution, selfReferenceInjection, signatoryRemoval
--                , timeBoundManipulation, tokenForgeryAttack simpleAlwaysSucceedsMintingPolicyV2 simpleTestAssetName
--                , unprotectedScriptOutput , unprotectedScriptOutput, valueUnderpaymentAttack]

-------------------------------------------------------------------------------
-- Helper functions for the AuctionModel
-------------------------------------------------------------------------------

-- | Available bidders (excluding the seller)
bidders :: [Wallet]
bidders = [MockWallet.w2, MockWallet.w3, MockWallet.w4, MockWallet.w5, MockWallet.w6, MockWallet.w7, MockWallet.w8, MockWallet.w9, MockWallet.w10]

-- | Create AuctionParams matching the model state.
paramsFromModel :: AuctionModel -> AuctionParams
paramsFromModel am =
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript) -- @TODO: use our own minting policy
      cs = CurrencySymbol . PlutusTx.toBuiltin . C.serialiseToRawBytes $ policyId
      endTime =
        case slotToUtcTime Defaults.eraHistory Defaults.systemStart (_endSlot am) of
          Left err -> error $ "paramsFromModel: cannot convert slot to posix time: " ++ show err
          Right t -> utcTimeToPosixTime t
   in AuctionParams
        { apSeller = transPubKeyHash $ verificationKeyHash (_seller am)
        , apCurrencySymbol = cs
        , apTokenName = tokenName "NFT" -- Dummy token name
        , apMinBid = fromInteger $ C.unCoin $ _minBid am
        , apEndTime = endTime
        }

-------------------------------------------------------------------------------
-- Property-Based Testing Functions
-------------------------------------------------------------------------------

-- | Prepare the auction by minting the NFT and locking it in the script.
prepareAuctionPBT
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => AuctionParams
  -- ^ Auction parameters
  -> m ()
prepareAuctionPBT params = do
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

  void $ tryBalanceAndSubmit mempty MockWallet.w1 lockTx TrailingChange []

-- | Place a bid in the auction for property-based testing.
placeBidPBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => AuctionParams
  -- ^ Auction parameters
  -> C.SlotNo
  -- ^ Current slot
  -> Maybe Wallet
  -- ^ Last Bidder wallet (Nothing if no bids)
  -> C.Lovelace
  -- ^ Last Bid amount
  -> Wallet
  -- ^ Bidder wallet
  -> C.Lovelace
  -- ^ Bid amount
  -> m ()
placeBidPBT params curSlot curHighestBidder curHighestBidAmount newBidder newBidAmount = do
  let an = unTransAssetName (apTokenName params)
  let policyId = C.hashScript (C.PlutusScript C.plutusScriptVersion mintingScript)
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Query the auction UTxO from the blockchain
  auctionUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null auctionUtxos) $ fail "No auction UTxO found on chain"

  let (txIn, _) = head auctionUtxos

  -- Create the new bid
  let newBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId newBidder
          , bPkh = transPubKeyHash $ verificationKeyHash newBidder
          , bAmount = fromInteger $ C.unCoin newBidAmount
          }
  let bidRedeemer = NewBid newBid
  let newDatum = AuctionDatum (Just newBid)

  -- New value = NFT + bid amount
  let nftOnly = BuildTx.assetValue policyId an 1
  let newValue = nftOnly <> C.lovelaceToValue newBidAmount

  setSlot curSlot

  -- Build the payout transaction
  let bidTx = case curHighestBidder of
        Nothing ->
          -- No bids: Return asset to seller
          execBuildTx $ do
            -- Set a validity range before auction end time
            BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
            -- Spend the script UTxO with redeemer
            BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
            -- Recreate script UTxO with updated datum and value
            BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue
        Just _bidderWallet ->
          -- Bids exist: Place another bid and refunds the last bidder
          execBuildTx $ do
            -- Set a validity range before auction end time
            BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
            -- Spend the script UTxO with redeemer
            BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) bidRedeemer
            -- Refund the last bidder exactly their bid amount
            for_ curHighestBidder $ \bidder ->
              BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidder) (C.lovelaceToValue curHighestBidAmount)
            -- Recreate script UTxO with updated datum and value
            BuildTx.payToScriptInlineDatum Defaults.networkId scriptHash newDatum C.NoStakeAddress newValue

  _ <- tryBalanceAndSubmit mempty newBidder bidTx TrailingChange []
  pure ()

-- | Close the auction and execute payout for property-based testing.
closeAuctionPBT
  :: (MonadMockchain C.ConwayEra m, MonadError (BalanceTxError C.ConwayEra) m, MonadFail m)
  => AuctionParams
  -- ^ Auction parameters
  -> C.SlotNo
  -- ^ Current slot (must be >= auction end time)
  -> Maybe Wallet
  -- ^ Highest bidder (Nothing if no bids)
  -> C.Lovelace
  -- ^ Highest bid amount
  -> m ()
closeAuctionPBT params curSlot highestBidder highestBidAmount = do
  let validator = C.PlutusScript C.plutusScriptVersion (auctionValidatorScript params)
  let scriptHash = C.hashScript validator

  -- Query the auction UTxO from the blockchain
  auctionUtxos <- utxosAt @C.ConwayEra scriptHash
  when (null auctionUtxos) $ fail "No auction UTxO found on chain"

  let (txIn, _) = head auctionUtxos
  utxo <- singleUTxO txIn
  let lockedNftValue = case utxo of
        Nothing -> error "UTxO not found for payout"
        Just txOut -> getTxOutValue txOut

  setSlot curSlot

  let payoutRedeemer = Payout

  -- Build the payout transaction
  let payoutTx = case highestBidder of
        Nothing ->
          -- No bids: Return asset to seller
          execBuildTx $ do
            BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
            BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
            -- Pay the NFT back to seller
            BuildTx.payToAddress
              (MockWallet.addressInEra Defaults.networkId MockWallet.w1)
              lockedNftValue
        Just bidderWallet ->
          -- Bids exist: Pay seller and bidder
          execBuildTx $ do
            BuildTx.addValidityRangeSlots curSlot (curSlot + 1)
            BuildTx.spendPlutusInlineDatum txIn (auctionValidatorScript params) payoutRedeemer
            -- Pay the bid amount to the seller
            BuildTx.payToAddress
              (MockWallet.addressInEra Defaults.networkId MockWallet.w1)
              (C.lovelaceToValue highestBidAmount)
            -- Pay the NFT to the highest bidder
            BuildTx.payToAddress (MockWallet.addressInEra Defaults.networkId bidderWallet) lockedNftValue

  _ <- tryBalanceAndSubmit mempty MockWallet.w1 payoutTx TrailingChange []
  pure ()
