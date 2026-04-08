{-# LANGUAGE OverloadedStrings #-}

module Main where

import Escrow.Spec.Prop (propBasedTests)
import Escrow.Spec.Unit (unitTests)
import Test.Tasty (TestTree, defaultMain, testGroup)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "escrow tests"
    [ unitTests
    , propBasedTests
    ]
