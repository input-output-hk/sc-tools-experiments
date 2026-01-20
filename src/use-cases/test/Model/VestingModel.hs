{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Model.VestingModel (
  VestingModel,
) where

import Cardano.Api qualified as C
import Contracts.Vesting qualified as Vesting
import Control.Monad.Except (runExceptT)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.PlutusLedger.V1 (transPubKeyHash)
import Convex.TestingInterface (Gen, TestingInterface (..))
import Convex.Utils (slotToUtcTime, utcTimeToPosixTime)
import Convex.Wallet (Wallet, verificationKeyHash)
import Convex.Wallet.MockWallet qualified as MockWallet
import GHC.Generics (Generic)
import PlutusLedgerApi.V1 (lovelaceValue)
import Test.QuickCheck.Gen qualified as Gen
import Test.Tasty.QuickCheck qualified as QC
import Utils.VestingUtils qualified as Utils

-------------------------------------------------------------------------------
-- Vesting Testing Interface
-------------------------------------------------------------------------------

{- | The scenario used in the property tests. It sets up a vesting scheme for a
  total of 60 ada over 20 blocks (20 ada can be taken out before
  that, at 10 blocks).
-}
mkVestingParams :: C.SlotNo -> Vesting.VestingParams
mkVestingParams startTime =
  -- error "mkVestingParams not implemented"
  let dt1 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (startTime + 10) of
        Left err -> error $ "mkVestingParams: cannot convert slot to utc time: " ++ show err
        Right t -> t
      dt2 = case slotToUtcTime Defaults.eraHistory Defaults.systemStart (startTime + 20) of
        Left err -> error $ "mkVestingParams: cannot convert slot to utc time: " ++ show err
        Right t -> t
   in Vesting.VestingParams
        { Vesting.vpOwner = transPubKeyHash $ verificationKeyHash MockWallet.w1
        , Vesting.vpTranche1 =
            Vesting.Vesting
              { Vesting.vDate = utcTimeToPosixTime $ dt1
              , Vesting.vAmount = lovelaceValue 20_000_000
              }
        , Vesting.vpTranche2 =
            Vesting.Vesting
              { Vesting.vDate = utcTimeToPosixTime $ dt2
              , Vesting.vAmount = lovelaceValue 40_000_000
              }
        }

data VestingModel = VestingModel
  { _vestedAmount :: C.Lovelace
  -- ^ How much value is in the contract
  , _vested :: [Wallet]
  -- ^ What wallets have already vested money
  , _t1Slot :: C.SlotNo
  -- ^ The time for the first tranche
  , _t2Slot :: C.SlotNo
  -- ^ The time for the second tranche
  , _t1Amount :: C.Lovelace
  -- ^ The size of the first tranche
  , _t2Amount :: C.Lovelace
  -- ^ The size of the second tranche
  }
  deriving (Show, Eq, Generic)

-- unstableMakeIsData ''VestingModel

vmDeadlineUpperBound :: Integer
vmDeadlineUpperBound = 1000

arbitraryTime :: Gen C.SlotNo
arbitraryTime = fromInteger <$> Gen.chooseInteger (0, vmDeadlineUpperBound)

instance TestingInterface VestingModel where
  data Action VestingModel
    = Vest Wallet
    | Retrieve Wallet C.Lovelace
    deriving (Show, Eq)

  initialState =
    VestingModel
      { _vestedAmount = mempty
      , _vested = []
      , _t1Slot = 10
      , _t2Slot = 20
      , _t1Amount = 20_000_000
      , _t2Amount = 40_000_000
      }

  arbitraryAction _vm =
    QC.oneof
      [ Vest <$> QC.elements MockWallet.mockWallets
      , Retrieve <$> QC.elements MockWallet.mockWallets <*> (fromInteger <$> Gen.chooseInteger (1_000_000, 60_000_000))
      ]

  precondition :: VestingModel -> Action VestingModel -> Bool
  precondition vm (Vest w) =
    -- error "precondition (Vest) not implemented"
    w `notElem` _vested vm -- After a wallet has vested the contract shuts down
      && transPubKeyHash (verificationKeyHash w) /= Vesting.vpOwner (mkVestingParams 0) -- The vesting owner shouldn't vest
      -- && slot < _t1Slot vm
  precondition _vm (Retrieve _w _amt) =
    -- error "precondition (Retrieve) not implemented"
    True -- Anyone can retrieve funds

  -- Vest the sum of the two tranches
  nextState vm (Vest w) =
    vm
      { _vestedAmount = _vestedAmount vm + _t1Amount vm + _t2Amount vm
      , _vested = w : _vested vm
      }
  -- Retrieve `v` value as long as that leaves enough value to satisfy
  -- the tranche requirements
  nextState vm (Retrieve _ amt) =
    vm
      { _vestedAmount = _vestedAmount vm - amt
      }

  perform vm (Vest _w) =
    do
      -- error "perform (Vest) not implemented"
      C.liftIO $ putStrLn $ "Locking some funds with the Vesting script: " ++ show vm
      runExceptT $
        Utils.lockVestingTest @C.ConwayEra (_t1Slot vm)
      >>= \case
        Left err -> fail $ "Locking funds script test failed: " <> show err
        Right _txId -> pure ()
  perform vm (Retrieve _w amt) =
    do
      -- error "perform (Retrieve) not implemented"
      C.liftIO $ putStrLn $ "Retrieving " ++ show amt ++ " lovelace from the Vesting script: " ++ show vm
      runExceptT $
        Utils.retrieveFundsTest @C.ConwayEra (_t1Slot vm) (_t1Slot vm) (_t2Slot vm) (_t2Slot vm + 5) amt -- @TODO: adjust slots
      >>= \case
        Left err -> fail $ "Retrieving funds script test failed: " <> show err
        Right _txId -> pure ()

  validate _vm = pure True

  monitoring _ _ = error "monitoring not implemented"
