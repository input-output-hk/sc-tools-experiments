{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

module Auction.Validator where

import Cardano.Api qualified as C
import Convex.PlutusTx (compiledCodeToScript)
import GHC.Generics (Generic)
import GHC.Real (Integral (toInteger))
import PlutusLedgerApi.V1 (Extended (..), Interval (..), LowerBound (..), POSIXTimeRange, UpperBound (..), lovelaceValueOf, toPubKeyHash, valueOf)
import PlutusLedgerApi.V1.Interval (contains)
import PlutusLedgerApi.V3 (CurrencySymbol, Datum (..), Lovelace, OutputDatum (..), POSIXTime, PubKeyHash, ScriptContext (..), ScriptInfo (..), TokenName, TxInfo (..), TxOut (..), from, getRedeemer, to)
import PlutusLedgerApi.V3.Contexts (getContinuingOutputs)
import PlutusTx qualified
import PlutusTx.Blueprint (HasBlueprintDefinition, definitionRef)
import PlutusTx.Bool (Bool (..))
import PlutusTx.Builtins.Internal (BuiltinByteString (..))
import PlutusTx.Eq ((==))
import PlutusTx.List qualified as List
import PlutusTx.Maybe (Maybe (..))
import PlutusTx.Ord ((>), (>=))
import PlutusTx.Prelude (BuiltinString, (&&), (.), (<>))
import PlutusTx.Prelude qualified as PlutusTx
import PlutusTx.Show qualified as PlutusTx
import Prelude (error, ($))

data AuctionParams = AuctionParams
  { apSeller :: PubKeyHash
  -- ^ Seller's public key hash
  , apCurrencySymbol :: CurrencySymbol
  -- ^ The currency symbol of the token being auctioned
  , apTokenName :: TokenName
  -- ^ The name of the token being auctioned
  , apMinBid :: Lovelace
  -- ^ The minimum bid in Lovelace
  , apEndTime :: POSIXTime
  -- ^ The deadline for placing a bid
  }

PlutusTx.makeLift ''AuctionParams

data Bid = Bid
  { bAddr :: PlutusTx.BuiltinByteString
  -- ^ Bidder's wallet address
  , bPkh :: PubKeyHash
  -- ^ Bidder's public key hash
  , bAmount :: Lovelace
  -- ^ Bid amount in Lovelace.
  }
  deriving stock (Generic)
  deriving anyclass (HasBlueprintDefinition)

PlutusTx.deriveShow ''Bid
PlutusTx.makeIsDataSchemaIndexed ''Bid [('Bid, 0)]

instance PlutusTx.Eq Bid where
  {-# INLINEABLE (==) #-}
  bid == bid' =
    bPkh bid
      PlutusTx.== bPkh bid'
      PlutusTx.&& bAmount bid
      PlutusTx.== bAmount bid'

{- | Datum represents the state of a smart contract. In this case
it contains the highest bid so far (if exists).
-}
newtype AuctionDatum = AuctionDatum {adHighestBid :: Maybe Bid}
  deriving stock (Generic)
  deriving newtype
    ( HasBlueprintDefinition
    , PlutusTx.ToData
    , PlutusTx.FromData
    , PlutusTx.UnsafeFromData
    )

{- | Redeemer is the input that changes the state of a smart contract.
In this case it is either a new bid, or a request to close the auction
and pay out the seller and the highest bidder.
-}
data AuctionRedeemer = NewBid Bid | Payout
  deriving stock (Generic)
  deriving anyclass (HasBlueprintDefinition)

PlutusTx.deriveShow ''AuctionRedeemer

PlutusTx.makeIsDataSchemaIndexed ''AuctionRedeemer [('NewBid, 0), ('Payout, 1)]

{- | Given the auction parameters, determines whether the transaction is allowed to
spend the UTXO. V3 validator extracts datum and redeemer from ScriptContext.
-}
{-# INLINEABLE auctionTypedValidator #-}
auctionTypedValidator :: AuctionParams -> ScriptContext -> Bool
auctionTypedValidator params ctx@(ScriptContext txInfo scriptRedeemer scriptInfo) =
  case redeemer of
    NewBid bid ->
      -- The new bid must be higher than the highest bid.
      -- If this is the first bid, it must be at least as high as the minimum bid.
      sufficientBid bid
        &&
        -- The bid is not too late.
        validBidTime
        &&
        -- The previous highest bid should be refunded.
        refundsPreviousHighestBid
        &&
        -- A correct new datum is produced, containing the new highest bid.
        correctOutput bid
    Payout ->
      -- The payout is not too early.
      validPayoutTime
        &&
        -- The seller gets the highest bid.
        sellerGetsHighestBid
        &&
        -- The highest bidder gets the asset.
        highestBidderGetsAsset
 where
  -- Extract redeemer from script context
  redeemer :: AuctionRedeemer
  redeemer = case PlutusTx.fromBuiltinData (getRedeemer scriptRedeemer) of
    Nothing -> PlutusTx.traceError "Failed to parse AuctionRedeemer"
    Just r -> r

  -- Extract datum from script context
  highestBid :: Maybe Bid
  highestBid = case scriptInfo of
    SpendingScript _ (Just (Datum datum)) ->
      case PlutusTx.fromBuiltinData datum of
        Just (AuctionDatum bid) -> bid
        Nothing -> PlutusTx.traceError "Failed to parse AuctionDatum"
    _ -> PlutusTx.traceError "Expected SpendingScript with datum"

  sufficientBid :: Bid -> Bool
  sufficientBid (Bid _ _ amt) = case highestBid of
    Just (Bid _ _ amt') -> amt > amt'
    Nothing -> amt >= apMinBid params

  validBidTime :: Bool
  ~validBidTime =
    PlutusTx.trace (showInterval $ txInfoValidRange txInfo) $
      to (apEndTime params) `contains` txInfoValidRange txInfo

  refundsPreviousHighestBid :: Bool
  ~refundsPreviousHighestBid = case highestBid of
    Nothing -> True
    Just (Bid _ bidderPkh amt) ->
      case List.find
        ( \o ->
            (toPubKeyHash (txOutAddress o) == Just bidderPkh)
              && (lovelaceValueOf (txOutValue o) == amt)
        )
        (txInfoOutputs txInfo) of
        Just _ -> True
        Nothing -> PlutusTx.traceError "Not found: refund script"

  currencySymbol :: CurrencySymbol
  currencySymbol = apCurrencySymbol params

  tokenName :: TokenName
  tokenName = apTokenName params

  correctOutput :: Bid -> Bool
  correctOutput bid = case getContinuingOutputs ctx of
    [o] ->
      let correctOutputDatum = case txOutDatum o of
            OutputDatum (Datum newDatum) -> case PlutusTx.fromBuiltinData newDatum of
              Just (AuctionDatum (Just bid')) ->
                PlutusTx.traceIfFalse
                  "Invalid output datum: contains a different Bid than expected"
                  (bid PlutusTx.== bid')
              Just (AuctionDatum Nothing) ->
                PlutusTx.traceError "Invalid output datum: expected Just Bid, got Nothing"
              Nothing ->
                PlutusTx.traceError "Failed to decode output datum"
            OutputDatumHash _ ->
              PlutusTx.traceError "Expected OutputDatum, got OutputDatumHash"
            NoOutputDatum ->
              PlutusTx.traceError "Expected OutputDatum, got NoOutputDatum"

          outValue = txOutValue o

          correctOutputValue =
            (lovelaceValueOf outValue PlutusTx.== bAmount bid)
              PlutusTx.&& (valueOf outValue currencySymbol tokenName PlutusTx.== 1)
       in correctOutputDatum PlutusTx.&& correctOutputValue
    os ->
      PlutusTx.traceError
        ( "Expected exactly one continuing output, got "
            PlutusTx.<> PlutusTx.show (List.length os)
        )

  validPayoutTime :: Bool
  ~validPayoutTime = from (apEndTime params) `contains` txInfoValidRange txInfo

  sellerGetsHighestBid :: Bool
  ~sellerGetsHighestBid = case highestBid of
    Nothing -> True
    Just bid ->
      case List.find
        ( \o ->
            (toPubKeyHash (txOutAddress o) == Just (apSeller params))
              && (lovelaceValueOf (txOutValue o) == bAmount bid)
        )
        (txInfoOutputs txInfo) of
        Just _ -> True
        Nothing -> PlutusTx.traceError "Not found: Output paid to seller"

  highestBidderGetsAsset :: Bool
  ~highestBidderGetsAsset =
    let highestBidder = case highestBid of
          -- If there are no bids, the asset should go back to the seller
          Nothing -> apSeller params
          Just bid -> bPkh bid
     in case List.find
          ( \o ->
              (toPubKeyHash (txOutAddress o) == Just highestBidder)
                && (valueOf (txOutValue o) currencySymbol tokenName == 1)
          )
          (txInfoOutputs txInfo) of
          Just _ -> True
          Nothing -> PlutusTx.traceError "Not found: Output paid to highest bidder"

{-# INLINEABLE auctionUntypedValidator #-}
auctionUntypedValidator
  :: AuctionParams
  -> PlutusTx.BuiltinData
  -> PlutusTx.BuiltinUnit
auctionUntypedValidator params ctx =
  PlutusTx.check
    ( auctionTypedValidator
        params
        (PlutusTx.unsafeFromBuiltinData ctx)
    )

{-# INLINEABLE hugeValidator' #-}
hugeValidator' :: AuctionParams -> PlutusTx.BuiltinData -> PlutusTx.BuiltinUnit
hugeValidator' params ctx =
  let big :: BuiltinByteString
      big = PlutusTx.replicateByte 50_000 0x41 -- 200KB
   in if PlutusTx.lengthOfByteString big >= 0
        then PlutusTx.check (auctionTypedValidator params (PlutusTx.unsafeFromBuiltinData ctx))
        else PlutusTx.traceError "impossible"

{-# INLINEABLE hugeValidator #-}
hugeValidator :: AuctionParams -> PlutusTx.BuiltinData -> PlutusTx.BuiltinUnit
hugeValidator params ctx =
  let _padding = hugePadding
   in PlutusTx.check $
        auctionTypedValidator params (PlutusTx.unsafeFromBuiltinData ctx)

{-# INLINEABLE hugePadding #-}
hugePadding :: BuiltinByteString
hugePadding =
  PlutusTx.appendByteString
    (PlutusTx.replicateByte 1 65)
    (PlutusTx.replicateByte 1 66)

-- | Compiling a parameterized validator for 'Scripts.Auction.auctionUntypedValidator'
hugeValidatorCompiled :: AuctionParams -> PlutusTx.CompiledCode (PlutusTx.BuiltinData -> PlutusTx.BuiltinUnit)
hugeValidatorCompiled params =
  case $$(PlutusTx.compile [||hugeValidator||])
    `PlutusTx.applyCode` PlutusTx.liftCodeDef params of
    PlutusTx.Left err -> error err
    PlutusTx.Right cc -> cc

-- | Serialized validator for 'Scripts.Auction.auctionUntypedValidator'
hugeValidatorScript :: AuctionParams -> C.PlutusScript C.PlutusScriptV3
hugeValidatorScript = compiledCodeToScript . hugeValidatorCompiled

-------------------------------------------------------------------------------
-- The functions below are used only for debugging purposes
-------------------------------------------------------------------------------

{-# INLINEABLE showPOSIXTime #-}
showPOSIXTime :: POSIXTime -> BuiltinString
showPOSIXTime t = PlutusTx.show $ toInteger t

{-# INLINEABLE showInterval #-}
showInterval :: POSIXTimeRange -> BuiltinString
showInterval (Interval l h) = "Interval: " <> showLowerBound l <> " to " <> showUpperBound h

{-# INLINEABLE showLowerBound #-}
showLowerBound :: LowerBound POSIXTime -> BuiltinString
showLowerBound (LowerBound NegInf _) = "negative infinity"
showLowerBound (LowerBound (Finite t) _) = PlutusTx.show $ toInteger t
showLowerBound (LowerBound PosInf _) = "positive infinity"

{-# INLINEABLE showUpperBound #-}
showUpperBound :: UpperBound POSIXTime -> BuiltinString
showUpperBound (UpperBound NegInf _) = "negative infinity"
showUpperBound (UpperBound (Finite t) _) = PlutusTx.show $ toInteger t
showUpperBound (UpperBound PosInf _) = "positive infinity"
