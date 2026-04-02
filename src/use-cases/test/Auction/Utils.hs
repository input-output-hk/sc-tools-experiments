{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Auction.Utils (
  mintingScript,
  getTxOutValue,
  utxosAt,
  getWalletAda,
) where

import Cardano.Api (txOutValueToLovelace)
import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Convex.Class (MonadMockchain)
import Convex.MockChain (utxoSet, walletUtxo)
import Convex.Utxos (toApiUtxo)
import Convex.Wallet (Wallet)

-------------------------------------------------------------------------------
-- Helper Functions
-------------------------------------------------------------------------------

-- | A simple minting script that always succeeds, used for testing purposes.
mintingScript :: C.PlutusScript C.PlutusScriptV1
mintingScript = C.examplePlutusScriptAlwaysSucceeds C.WitCtxMint

{- | Extracts the value from a transaction output.
  This function assumes that the transaction output is using the Shelley-based value representation,
  which is the case for Babbage and later eras.
-}
getTxOutValue :: C.TxOut C.CtxUTxO C.ConwayEra -> C.Value
getTxOutValue (C.TxOut _ (C.TxOutValueShelleyBased _ val) _ _) = C.fromMaryValue val

-- | Fetches the UTxOs at a given script address identified by its script hash.
utxosAt
  :: forall era m
   . (MonadMockchain era m, MonadFail m, C.IsBabbageBasedEra era)
  => C.ScriptHash -> m [(C.TxIn, C.TxOut C.CtxUTxO era)]
utxosAt scriptHash = do
  utxos <- utxoSet
  let scriptUtxos =
        [ (txIn, txOut)
        | (txIn, txOut@(C.TxOut addr _ _ _)) <- C.UTxO.toList (toApiUtxo utxos)
        , isScriptAddress addr
        ]
  pure scriptUtxos
 where
  isScriptAddress (C.AddressInEra _ (C.ShelleyAddress _ (ScriptHashObj h) _)) =
    h == C.toShelleyScriptHash scriptHash
  isScriptAddress _ = False

-- | Helper function to get the total ADA balance of a wallet by summing the values of its UTxOs.
getWalletAda
  :: (MonadMockchain C.ConwayEra m)
  => Wallet
  -> m Double
getWalletAda wallet = do
  utxos <- walletUtxo wallet

  let lov = sum [C.unCoin $ txOutValueToLovelace v | (_, C.TxOut _ v _ _) <- C.UTxO.toList (toApiUtxo @C.ConwayEra utxos)]

      ada :: Double
      ada = fromIntegral lov / 1_000_000

  return ada
