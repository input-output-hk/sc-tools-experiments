{-# LANGUAGE TypeApplications #-}

module Vesting.Spec.Prop (
  propBasedTests,
) where

import Convex.TestingInterface (RunOptions, propRunActions, propRunActionsWithOptions)
import Test.Tasty (TestTree, testGroup)
import Vesting.Model (VestingModel)

-------------------------------------------------------------------------------
-- Property-based tests for the Vesting script
-------------------------------------------------------------------------------

propBasedTests :: RunOptions -> TestTree
propBasedTests runOpts =
  testGroup
    "property-based tests"
    [ propRunActionsWithOptions @VestingModel "Property-based test vesting script" runOpts
    ]
