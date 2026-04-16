{-# LANGUAGE OverloadedStrings #-}

module Main where

import Convex.Tasty.Streaming (defaultMainStreaming)
import MultiPlayerPingPong.Spec.Prop (propBasedTests)
import MultiPlayerPingPong.Spec.Unit (unitTests)
import Test.Tasty (TestTree, testGroup)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMainStreaming tests

tests :: TestTree
tests =
  testGroup
    "multi-player ping-pong tests"
    [ unitTests
    , propBasedTests
    ]
