{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE TypeApplications #-}

import Control.Exception (catch, throwIO)
import Data.IORef (IORef, newIORef, readIORef)
import PlutusTx.Coverage (CoverageData, CoverageReport (CoverageReport))
import Prettyprinter qualified as Pretty
import System.Exit (ExitCode)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck (testProperty)

import Convex.MockChain.Utils (
  Options (coverageRef),
  defaultOptions,
  mockchainFails,
  mockchainFailsWithOptions,
  mockchainSucceedsWithOptions,
  modifyTransactionLimits,
 )
import Convex.TestingInterface (
  RunOptions (mcOptions),
  defaultRunOptions,
  propRunActionsWithOptions,
 )
import Convex.Utils (failOnError)

import BountySpec (
  propBountySecureAgainstDoubleSatisfaction,
  propBountyVulnerableToDoubleSatisfaction,
 )
import PingPongSpec (
  PingPongModel,
  pingPongMultipleRounds,
  propPingPongSecureAgainstOutputRedirect,
  propPingPongVulnerableToOutputRedirect,
  propPingPongWithThreatModel,
 )
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
        , testGroup
            "ping-pong"
            [ testCase
                "Ping and Pong should succeed"
                ( mockchainSucceedsWithOptions opts $
                    failOnError
                      (pingPongMultipleRounds Scripts.Pinged [Scripts.Pong])
                )
            , testCase
                "Pong and Ping should succeed"
                ( mockchainSucceedsWithOptions opts $
                    failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Ping])
                )
            , testCase
                "Ping and Ping should fail"
                ( mockchainFailsWithOptions
                    opts
                    (failOnError (pingPongMultipleRounds Scripts.Pinged [Scripts.Ping]))
                    -- Test tree fails
                    (\_ -> pure ())
                )
            , testCase
                "Pong and Pong should fail"
                ( mockchainFailsWithOptions
                    opts
                    (failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Pong]))
                    -- Test tree fails
                    (\_ -> pure ())
                )
            , testCase
                "Stop after Ping should succeed"
                ( mockchainSucceedsWithOptions opts $
                    failOnError (pingPongMultipleRounds Scripts.Ponged [Scripts.Ping, Scripts.Stop])
                )
            , testCase
                "Stop after Pong should succeed"
                ( mockchainSucceedsWithOptions opts $
                    failOnError (pingPongMultipleRounds Scripts.Pinged [Scripts.Pong, Scripts.Stop])
                )
            , testCase
                "Stop after Stop should fail"
                ( mockchainFailsWithOptions
                    opts
                    (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Stop]))
                    -- Test tree fails
                    (\_ -> pure ())
                )
            , testCase
                "Ping after Stop should fail"
                ( mockchainFailsWithOptions
                    opts
                    (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Ping]))
                    -- Test tree fails
                    (\_ -> pure ())
                )
            , testCase
                "Pong after Stop should fail"
                ( mockchainFailsWithOptions
                    opts
                    (failOnError (pingPongMultipleRounds Scripts.Stopped [Scripts.Pong]))
                    -- Test tree fails
                    (\_ -> pure ())
                )
            , testProperty
                "Property-based test with TestingInterface"
                (propRunActionsWithOptions @PingPongModel runOpts)
            , testProperty
                "Property-based test with ThreatModel integration"
                (propPingPongWithThreatModel runOpts)
            , testProperty
                "PingPong VULNERABLE to unprotected output redirect"
                (propPingPongVulnerableToOutputRedirect threatModelOpts)
            , testProperty
                "PingPong SECURE against unprotected output redirect"
                (propPingPongSecureAgainstOutputRedirect threatModelOpts)
            ]
        , testGroup
            "bounty (double satisfaction)"
            [ testProperty
                "Bounty VULNERABLE to double satisfaction"
                (propBountyVulnerableToDoubleSatisfaction threatModelOpts)
            , testProperty
                "Bounty SECURE against double satisfaction"
                (propBountySecureAgainstDoubleSatisfaction threatModelOpts)
            ]
        ]
    ]
 where
  -- Use 25000 byte limit because the secure PingPong validator is larger
  opts = modifyTransactionLimits (defaultOptions{coverageRef = Just ref}) 25000
  runOpts = defaultRunOptions{mcOptions = opts}
  threatModelOpts = runOpts
