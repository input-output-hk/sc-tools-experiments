{-# LANGUAGE TypeApplications #-}

module Vesting.Spec.Prop (
  propBasedTests,
) where

import Convex.TestingInterface (propRunActions)
import Test.Tasty (TestTree, testGroup)
import Vesting.Model (VestingModel)

-------------------------------------------------------------------------------
-- Property-based tests for the Vesting script
-------------------------------------------------------------------------------

propBasedTests :: TestTree
propBasedTests =
  testGroup
    "property-based tests"
    [ propRunActions @VestingModel "Property-based test vesting script"
    ]
