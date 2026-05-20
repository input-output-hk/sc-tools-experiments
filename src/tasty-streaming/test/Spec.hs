module Main (main) where

import Convex.Tasty.SrcLocSpec qualified as SrcLocSpec
import Convex.Tasty.Streaming (defaultMainStreaming)
import Test.Tasty (testGroup)

main :: IO ()
main =
  defaultMainStreaming $
    testGroup
      "convex-tasty-streaming"
      [SrcLocSpec.tests]
