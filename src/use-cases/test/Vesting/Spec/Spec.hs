{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

import Cardano.Api qualified as C
import Cardano.Api.Ledger qualified as Ledger
import Cardano.Ledger.Plutus.ExUnits (ExUnits (exUnitsMem))
import Control.Lens ((%~), (&))
import Convex.NodeParams (NodeParams (..))
import Convex.NodeParams qualified as NP
import Convex.TestingInterface (Options (..), RunOptions (..), defaultOptions, defaultRunOptions)
import Data.Functor.Identity (Identity)
import Test.Tasty (
  TestTree,
  defaultMain,
  testGroup,
 )

-- import Vesting.Spec.Prop qualified

import Vesting.Spec.Prop qualified
import Vesting.Spec.Unit qualified

modifyMemoryLimit :: Options C.ConwayEra -> Options C.ConwayEra
modifyMemoryLimit opts =
  let
    params0 = params opts
    C.LedgerProtocolParameters (Ledger.PParams ppHkd) = npProtocolParameters params0
    ppHkd' =
      ppHkd
        & NP.hkdMaxTxExUnitsL @_ @Identity
          %~ (\ex -> ex{exUnitsMem = 30_000_000})
   in
    opts
      { params =
          params0
            { npProtocolParameters =
                C.LedgerProtocolParameters (Ledger.PParams ppHkd')
            }
      }

main :: IO ()
main =
  let
    opts = modifyMemoryLimit defaultOptions
    runOpts = defaultRunOptions{mcOptions = opts}
   in
    defaultMain (tests opts runOpts)

tests :: Options C.ConwayEra -> RunOptions -> TestTree
tests _opts runOpts =
  testGroup
    "vesting tests"
    [ Vesting.Spec.Unit.unitTests
    , Vesting.Spec.Prop.propBasedTests runOpts
    ]
