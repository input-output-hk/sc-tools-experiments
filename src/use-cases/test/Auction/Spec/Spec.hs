{-# LANGUAGE OverloadedStrings #-}

module Main where

import Auction.Spec.Attacks (attackTests)
import Auction.Spec.Prop (propBasedTests)
import Auction.Spec.Unit (unitTests)
import Test.Tasty (TestTree, defaultMain, testGroup)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "auction tests"
    [ unitTests
    , attackTests
    , propBasedTests
    ]
