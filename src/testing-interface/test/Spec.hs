{-# LANGUAGE NumericUnderscores #-}

import Cardano.Api qualified as C
import Convex.MockChain.Utils (mockchainFails)
import Convex.TestingInterface (
  CoverageConfig (..),
  Options,
  RunOptions (mcOptions),
  mockchainSucceedsWithOptions,
  modifyTransactionLimits,
  printCoverageReport,
  silentCoverageReport,
  withCoverage,
 )
import Convex.Utils (failOnError)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (testCase)

import AikenBankSpec (aikenBankTests)
import AikenHelloWorldSpec (aikenHelloWorldTests)
import AikenKingOfCardanoSpec (aikenKingOfCardanoTests)
import AikenLendingSpec (aikenLendingTests)
import AikenMultisigTreasurySpec (aikenMultisigTreasuryTests)
import AikenMultisigTreasuryV2Spec (aikenMultisigTreasuryV2Tests)
import AikenMultisigTreasuryV3Spec (aikenMultisigTreasuryV3Tests)
import AikenPingPongSpec (aikenPingPongTests)
import AikenPurchaseOfferSpec (aikenPurchaseOfferTests)
import AikenSellNftSpec (aikenSellNftTests)
import AikenSpec (aikenTests)
import AikenTipJarSpec (aikenTipJarTests)
import AikenTipJarV2Spec (aikenTipJarV2Tests)
import AikenVestingSpec (aikenVestingTests)
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
      , coverageReport = silentCoverageReport
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
    , aikenTests opts
    , aikenBankTests runOpts
    , aikenHelloWorldTests runOpts
    , aikenKingOfCardanoTests runOpts
    , aikenLendingTests runOpts
    , aikenMultisigTreasuryTests runOpts
    , aikenMultisigTreasuryV2Tests runOpts
    , aikenMultisigTreasuryV3Tests runOpts
    , aikenPingPongTests runOpts
    , aikenPurchaseOfferTests runOpts
    , aikenSellNftTests runOpts
    , aikenTipJarTests runOpts
    , aikenTipJarV2Tests runOpts
    , aikenVestingTests runOpts
    ]
