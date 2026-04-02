{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

import Cardano.Api (txOutValueToLovelace)
import Cardano.Api qualified as C
import Contracts.AuctionValidator (AuctionDatum (AuctionDatum), AuctionParams (..), AuctionRedeemer (NewBid), Bid (Bid, bAddr, bAmount, bPkh))
import Control.Monad (ap, void)
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadBlockchain (utxoByTxIn), MonadMockchain, setSlot, singleUTxO)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain (utxoSet)
import Convex.MockChain.CoinSelection (tryBalanceAndSubmit)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.PlutusLedger.V1 (transPubKeyHash, transValue, unTransAssetName, unTransTxOutValue, unTransValue)
import Convex.TestingInterface (propRunActions)
import Convex.Utils (failOnError, inBabbage)
import Convex.Utils.String (unsafeAssetName)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet qualified as MockWallet
import Convex.Wallet.MockWallet qualified as MockWallet
import Data.Set qualified as Set
import PlutusLedgerApi.Common qualified as PlutusTx
import PlutusLedgerApi.V1 (CurrencySymbol (..), FromData (fromBuiltinData), POSIXTime (..), TokenName (..), TxOut (txOutValue), currencySymbol, fromBuiltin, lovelaceValue, singleton, tokenName)
import Scripts.AuctionScript (auctionValidatorScript)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (testProperty)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "auction tests"
    [ unitTests
    -- , propBasedTests
    ]

-------------------------------------------------------------------------------
-- Unit tests for the Auction script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ testCase
        "First bid equals minimum bid"
        (mockchainSucceeds $ failOnError firstBidEqualsMinimumTest)
    ]

-------------------------------------------------------------------------------
-- Property-based tests for the Auction script
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests = undefined

-------------------------------------------------------------------------------
-- Helper Functions
-------------------------------------------------------------------------------

mintingScript :: C.PlutusScript C.PlutusScriptV1
mintingScript = C.examplePlutusScriptAlwaysSucceeds C.WitCtxMint

getTxOutValue :: C.TxOut C.CtxUTxO C.ConwayEra -> C.Value
getTxOutValue (C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) = C.fromMaryValue val

-------------------------------------------------------------------------------
-- Unit Testing Functions
-------------------------------------------------------------------------------

firstBidEqualsMinimumTest
  :: (MonadMockchain C.ConwayEra m, MonadFail m, MonadError (BalanceTxError C.ConwayEra) m)
  => m ()
firstBidEqualsMinimumTest = do
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

  -- let asset = C.assetClass (apCurrencySymbol params) (apTokenName params)
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
  -- <> C.lovelaceToValue 2_000_000
  -- 2 ADA of lovelace is added because every UTxO on Cardano must
  -- contain a minimum amount of lovelace (min-UTxO deposit).
  -- Replaced by BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

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

  -- Get the value of the locked UTxO
  utxo <- singleUTxO txIn

  let scriptInputValue = case utxo of
        Nothing -> error "UTxO not found"
        Just txOut -> getTxOutValue txOut

  -- Create a bid equal to minimum bid
  let bidder = MockWallet.w2
      bidAmount = apMinBid params -- exactly the minimum
      firstBid =
        Bid
          { bAddr = PlutusTx.toBuiltin $ C.serialiseToRawBytes $ MockWallet.address Defaults.networkId bidder
          , bPkh = transPubKeyHash $ verificationKeyHash bidder
          , bAmount = bidAmount
          }
      bidRedeemer = NewBid firstBid
      newDatum = AuctionDatum (Just firstBid)
      newValue = scriptInputValue <> C.lovelaceToValue 10_000_000

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
          -- @TODO: check if it is necessary -> Min ADA adjustment
          BuildTx.setMinAdaDepositAll Defaults.bundledProtocolParameters

  -- Submit the bid transaction from wallet 2 (the bidder)
  _ <- tryBalanceAndSubmit mempty bidder bidTx TrailingChange []

  return ()
