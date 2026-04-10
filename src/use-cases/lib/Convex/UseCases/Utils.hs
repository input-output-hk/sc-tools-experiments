{-# LANGUAGE TypeFamilies #-}

module Convex.UseCases.Utils (
  utxosAt,
) where

import Cardano.Api qualified as C
import Cardano.Api.UTxO qualified as C.UTxO
import Cardano.Ledger.Shelley.API (Credential (ScriptHashObj))
import Convex.Class (MonadMockchain)
import Convex.MockChain (utxoSet)
import Convex.Utxos (toApiUtxo)

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
