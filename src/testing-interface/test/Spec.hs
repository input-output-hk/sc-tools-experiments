{-# LANGUAGE NumericUnderscores #-}

import Control.Exception (catch, throwIO)
import Data.IORef (IORef, newIORef, readIORef)
import PlutusTx.Coverage (CoverageData, CoverageReport (CoverageReport))
import Prettyprinter qualified as Pretty
import System.Exit (ExitCode)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (testCase)

import Convex.MockChain.Utils (
  Options (coverageRef),
  defaultOptions,
  mockchainFails,
  mockchainSucceedsWithOptions,
  modifyTransactionLimits,
 )
import Convex.TestingInterface (
  RunOptions (mcOptions),
  defaultRunOptions,
 )
import Convex.Utils (failOnError)

import BountySpec (bountyTests)
import PingPongCoverageSpec (pingPongCoverageTests)
import PingPongSpec (pingPongTests)
import SampleSpec (sampleScriptTest)
import Scripts (pingPongCovIdx)
import Scripts qualified

main :: IO ()
main = do
  ref <- newIORef mempty
  defaultMain (tests ref)
    `catch` ( \(e :: ExitCode) -> do
                covData <- readIORef ref
                let report = CoverageReport pingPongCovIdx covData
                print $ Pretty.pretty report
                throwIO e
            )

tests :: IORef CoverageData -> TestTree
tests ref =
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
 where
  -- Use 30000 byte limit because the secure PingPong validator is larger
  opts = modifyTransactionLimits (defaultOptions{coverageRef = Just ref}) 30_000
  runOpts = defaultRunOptions{mcOptions = opts}
