{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE TypeApplications #-}

module SampleSpec (
  -- * Test functions
  sampleScriptTest,
) where

import Cardano.Api qualified as C
import Control.Monad.Except (MonadError)
import Convex.BuildTx (execBuildTx)
import Convex.BuildTx qualified as BuildTx
import Convex.Class (MonadMockchain)
import Convex.CoinSelection (BalanceTxError, ChangeOutputPosition (TrailingChange))
import Convex.MockChain.CoinSelection (
  tryBalanceAndSubmit,
 )
import Convex.MockChain.Defaults qualified as Defaults
import Convex.Wallet.MockWallet qualified as Wallet
import Scripts qualified

plutusScript :: (C.IsPlutusScriptLanguage lang) => C.PlutusScript lang -> C.Script lang
plutusScript = C.PlutusScript C.plutusScriptVersion

sampleScriptTest
  :: forall era m
   . ( MonadMockchain era m
     , MonadError (BalanceTxError era) m
     , MonadFail m
     , C.IsBabbageBasedEra era
     , C.HasScriptLanguageInEra C.PlutusScriptV3 era
     )
  => Scripts.SampleRedeemer
  -> m ()
sampleScriptTest redeemer = do
  let txBody =
        execBuildTx
          ( BuildTx.payToScriptDatumHash
              Defaults.networkId
              (plutusScript Scripts.sampleValidatorScript)
              ()
              C.NoStakeAddress
              (C.lovelaceToValue 10_000_000)
          )
  -- here is the locking !!!
  input <- C.TxIn . C.getTxId . C.getTxBody <$> tryBalanceAndSubmit mempty Wallet.w1 txBody TrailingChange [] <*> pure (C.TxIx 0)

  -- Spend!! the outputs in a single transaction
  _tx <- tryBalanceAndSubmit mempty Wallet.w1 (execBuildTx $ Scripts.spendSample redeemer input) TrailingChange []
  pure ()
