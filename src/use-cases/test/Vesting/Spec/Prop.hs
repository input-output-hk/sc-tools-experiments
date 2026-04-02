{-# LANGUAGE TypeApplications #-}

module Vesting.Spec.Prop (
  propBasedTests,
) where

import Convex.TestingInterface (propRunActions)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty)
import Vesting.Model (VestingModel)

-------------------------------------------------------------------------------
-- Property-based tests for the Vesting script
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ testProperty "Property-based test vesting script" (propRunActions @VestingModel)
    ]
