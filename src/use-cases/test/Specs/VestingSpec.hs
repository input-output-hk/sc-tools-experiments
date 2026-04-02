{-# LANGUAGE TypeApplications #-}

module Specs.VestingSpec (
  unitTests,
  propBasedTests,
) where

import Cardano.Api qualified as C
import Convex.MockChain.Utils (mockchainFails, mockchainSucceeds)
import Convex.TestingInterface (propRunActions)
import Convex.Utils (failOnError)
import Model.VestingModel (VestingModel)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (testProperty)
import Utils.VestingUtils qualified as Utils

-------------------------------------------------------------------------------
-- Unit tests for the Vesting script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    [ testCase
        "secure some funds with the vesting script"
        (mockchainSucceeds $ failOnError (Utils.lockVestingTest @C.ConwayEra 10))
    , testCase
        "retrieve some funds"
        (mockchainSucceeds $ failOnError (Utils.retrieveFundsTest @C.ConwayEra 10 10 20 10 10_000_000))
    , testCase
        "cannot retrieve more than allowed"
        (mockchainFails (failOnError (Utils.retrieveFundsTest @C.ConwayEra 10 10 20 15 30_000_000)) (\_ -> pure ()))
    , testCase
        "can retrieve everything at the end"
        (mockchainSucceeds $ failOnError (Utils.retrieveFundsTest @C.ConwayEra 10 15 30 20 58_775_000))
    , testCase
        "can retrieve in steps according to the vesting schedule"
        (mockchainSucceeds $ failOnError (Utils.retrieveFundsInSteps @C.ConwayEra 10 15))
    ]

-------------------------------------------------------------------------------
-- Property-based tests for the Vesting script
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ testProperty "Property-based test vesting script" (propRunActions @VestingModel)
    ]
