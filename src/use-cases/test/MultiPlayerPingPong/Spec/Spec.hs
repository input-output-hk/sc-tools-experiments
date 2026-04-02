{-# LANGUAGE OverloadedStrings #-}

module Main where

import MultiPlayerPingPong.Spec.Prop (propBasedTests)
import MultiPlayerPingPong.Spec.Unit (unitTests)
import Test.Tasty (TestTree, defaultMain, testGroup)

--------------------------------------------------------------------------------
-- Main Test Entry Point
--------------------------------------------------------------------------------

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "multi-player ping-pong tests"
    [ unitTests
    , propBasedTests
    ]
