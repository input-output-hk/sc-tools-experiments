{-# LANGUAGE NumericUnderscores #-}

import Cardano.Api qualified as C
import Convex.MockChain.Utils (
  Options,
  mockchainFails,
  mockchainSucceedsWithOptions,
  modifyTransactionLimits,
 )
import Convex.TestingInterface (
  CoverageConfig (..),
  RunOptions (mcOptions),
  printCoverageReport,
  withCoverage,
 )
import Convex.Utils (failOnError)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (testCase)

import BountySpec (bountyTests)
import PingPongCoverageSpec (pingPongCoverageTests)
import PingPongSpec (pingPongTests)
import SampleSpec (sampleScriptTest)
import Scripts (pingPongCovIdx)
import Scripts qualified

main :: IO ()
main = withCoverage config $ \opts0 runOpts0 ->
  let
    -- Use 30000 byte limit because the secure PingPong validator is larger
    opts = modifyTransactionLimits opts0 30_000
    runOpts = runOpts0{mcOptions = opts}
   in
    defaultMain (tests opts runOpts)
 where
  config =
    CoverageConfig
      { coverageIndices = [pingPongCovIdx]
      , coverageReport = printCoverageReport
      }

tests :: Options C.ConwayEra -> RunOptions -> TestTree
tests opts runOpts =
  testGroup
    "testing-interface tests"
    [ testGroup
        "ha scripts"
        [ testCase "spend an output succeeds" (mockchainSucceedsWithOptions opts $ failOnError (sampleScriptTest (Scripts.SampleRedeemer True True)))
        , testCase
            "spend an output fails"
            ( mockchainFails
                (failOnError (sampleScriptTest (Scripts.SampleRedeemer False True)))
                -- Test tree fails
                (\_ -> pure ())
            )
        , pingPongTests opts runOpts
        , bountyTests runOpts
        , pingPongCoverageTests opts
        ]
    ]
