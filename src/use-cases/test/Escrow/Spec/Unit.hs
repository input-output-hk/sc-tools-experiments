{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Escrow.Spec.Unit where

import Test.Tasty (TestTree, testGroup)

-------------------------------------------------------------------------------
-- Unit tests for the Escrow script
-------------------------------------------------------------------------------

unitTests :: TestTree
unitTests =
  testGroup
    "unit tests"
    []
