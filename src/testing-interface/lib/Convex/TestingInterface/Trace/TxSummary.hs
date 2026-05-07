{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

module Convex.TestingInterface.Trace.TxSummary (
  summarizeTx,
  summarizeTxBody,
  renderAddress,
  toValueSummary,
) where

import Cardano.Api qualified as C
import Convex.TestingInterface.Trace (
  AssetSummary (..),
  TxInputSummary (..),
  TxOutputSummary (..),
  TxSummary (..),
  ValueSummary (..),
 )
import Data.ByteString qualified as BS
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as Text
import Data.Text.Encoding qualified as TE
import GHC.Exts (toList)

-- | Summarize a full transaction, resolving inputs from the given UTxO set.
summarizeTx :: C.Tx C.ConwayEra -> C.UTxO C.ConwayEra -> TxSummary
summarizeTx tx utxo =
  let body = C.getTxBody tx
      txId = C.getTxId body
      summary = summarizeTxBody body utxo
   in summary{txsId = Just (C.serialiseToRawBytesHexText txId)}

-- | Summarize a transaction body, resolving inputs from the given UTxO set.
summarizeTxBody :: C.TxBody C.ConwayEra -> C.UTxO C.ConwayEra -> TxSummary
summarizeTxBody body (C.UTxO utxoMap) =
  let content = C.getTxBodyContent body

      -- Inputs (resolved from UTxO)
      inputTxIns = map fst (C.txIns content)
      inputs =
        [ mkInputSummary txIn txOut
        | txIn <- inputTxIns
        , Just txOut <- [Map.lookup txIn utxoMap]
        ]

      -- Outputs
      outputs = zipWith (mkOutputSummary (C.getTxId body)) [0 ..] (C.txOuts content)

      -- Fee
      fee = case C.txFee content of
        C.TxFeeExplicit _ coin -> C.unCoin coin

      -- Mint
      mint = case C.txMintValue content of
        C.TxMintNone -> Nothing
        mv@C.TxMintValue{} ->
          let v = C.txMintValueToValue mv
           in if v == mempty then Nothing else Just (toValueSummary v)

      -- Required signers
      signers = case C.txExtraKeyWits content of
        C.TxExtraKeyWitnessesNone -> []
        C.TxExtraKeyWitnesses _ hashes -> map C.serialiseToRawBytesHexText hashes

      -- Validity range
      validRange =
        renderValidityRange
          (C.txValidityLowerBound content)
          (C.txValidityUpperBound content)
   in TxSummary
        { txsId = Nothing
        , txsInputs = inputs
        , txsOutputs = outputs
        , txsMint = mint
        , txsFee = fee
        , txsSigners = signers
        , txsValidRange = validRange
        }

-- | Build an input summary from a TxIn and its resolved TxOut.
mkInputSummary :: C.TxIn -> C.TxOut C.CtxUTxO C.ConwayEra -> TxInputSummary
mkInputSummary txIn (C.TxOut addr val _datum _refScript) =
  TxInputSummary
    { tisUtxo = renderTxIn txIn
    , tisAddress = renderAddressInEra addr
    , tisValue = toValueSummary (C.txOutValueToValue val)
    }

-- | Build an output summary from a TxId, an index, and a TxOut.
mkOutputSummary :: C.TxId -> Int -> C.TxOut C.CtxTx C.ConwayEra -> TxOutputSummary
mkOutputSummary txId idx (C.TxOut addr val datum _refScript) =
  TxOutputSummary
    { tosUtxo = renderTxIn (C.TxIn txId (C.TxIx (fromIntegral idx)))
    , tosAddress = renderAddressInEra addr
    , tosValue = toValueSummary (C.txOutValueToValue val)
    , tosDatum = renderDatum datum
    }

-- ---------------------------------------------------------------------
-- Rendering helpers
-- ---------------------------------------------------------------------

-- | Render a TxIn as @"txid#index"@.
renderTxIn :: C.TxIn -> Text
renderTxIn (C.TxIn txId (C.TxIx ix)) =
  C.serialiseToRawBytesHexText txId <> "#" <> Text.pack (show ix)

-- | Render an AddressInEra as bech32 text.
renderAddressInEra :: C.AddressInEra C.ConwayEra -> Text
renderAddressInEra (C.AddressInEra C.ShelleyAddressInEra{} addr) = C.serialiseAddress addr
renderAddressInEra (C.AddressInEra C.ByronAddressInAnyEra{} addr) = Text.pack (show addr)

-- | Render a Shelley address as bech32 text.
renderAddress :: C.Address C.ShelleyAddr -> Text
renderAddress = C.serialiseAddress

-- | Build a structured ValueSummary from a cardano-api Value.
toValueSummary :: C.Value -> ValueSummary
toValueSummary val =
  let items = toList val -- [(AssetId, Quantity)]
      lovelace = sum [n | (C.AdaAssetId, C.Quantity n) <- items]
      assets = [toAssetSummary pid name qty | (C.AssetId pid name, C.Quantity qty) <- items]
   in ValueSummary
        { vsLovelace = lovelace
        , vsAssets = assets
        }

toAssetSummary :: C.PolicyId -> C.AssetName -> Integer -> AssetSummary
toAssetSummary pid name qty =
  AssetSummary
    { asPolicyId = C.serialiseToRawBytesHexText pid -- FULL hex, no truncation
    , asName = renderAssetName name -- UTF-8 or hex fallback
    , asQuantity = qty
    }

-- | Render an AssetName as text, trying UTF-8 decoding first.
renderAssetName :: C.AssetName -> Text
renderAssetName an =
  let C.UnsafeAssetName bs = an
   in if BS.null bs
        then "<empty>"
        else case TE.decodeUtf8' bs of
          Right t -> t
          Left _ -> C.serialiseToRawBytesHexText an

-- | Render a datum reference for a transaction output.
renderDatum :: C.TxOutDatum C.CtxTx C.ConwayEra -> Maybe Text
renderDatum C.TxOutDatumNone = Nothing
renderDatum (C.TxOutDatumHash _ h) = Just ("hash:" <> C.serialiseToRawBytesHexText h)
renderDatum (C.TxOutSupplementalDatum _ d) =
  Just ("supplemental:" <> C.serialiseToRawBytesHexText (C.hashScriptDataBytes d))
renderDatum (C.TxOutDatumInline _ d) =
  Just ("inline:" <> C.serialiseToRawBytesHexText (C.hashScriptDataBytes d))

-- | Render validity range as text. Returns @Nothing@ for unbounded ranges.
renderValidityRange
  :: C.TxValidityLowerBound C.ConwayEra
  -> C.TxValidityUpperBound C.ConwayEra
  -> Maybe Text
renderValidityRange lower upper =
  case (lower, upper) of
    (C.TxValidityNoLowerBound, C.TxValidityUpperBound _ Nothing) ->
      Nothing -- unbounded, no need to show
    _ ->
      Just (renderLower lower <> " - " <> renderUpper upper)
 where
  renderLower C.TxValidityNoLowerBound = "(-inf"
  renderLower (C.TxValidityLowerBound _ (C.SlotNo n)) = "[" <> Text.pack (show n)
  renderUpper (C.TxValidityUpperBound _ Nothing) = "+inf)"
  renderUpper (C.TxValidityUpperBound _ (Just (C.SlotNo n))) = Text.pack (show n) <> ")"
