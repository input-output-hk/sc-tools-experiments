{-# LANGUAGE OverloadedStrings #-}

module Main where

import Auction.Spec.Attacks (attackTests)
import Auction.Spec.Prop (propBasedTests)
import Auction.Spec.Unit (unitTests)
import Convex.Tasty.Streaming (defaultMainStreaming)
import Test.Tasty (TestTree, testGroup)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMainStreaming tests

tests :: TestTree
tests =
  testGroup
    "auction tests"
    [ unitTests
    , attackTests
    , propBasedTests
    ]
