{-# LANGUAGE NumericUnderscores #-}

import Cardano.Api qualified as C
import Convex.MockChain.Utils (mockchainFails)
import Convex.Tasty.HUnit (testCase)
import Convex.Tasty.Streaming (streamingIngredients)
import Convex.TestingInterface (
  CoverageConfig (..),
  Options,
  RunOptions (mcOptions, threatModelFilter),
  mockchainSucceedsWithOptions,
  modifyTransactionLimits,
  withCoverage,
  writeCoverageReport,
 )
import Convex.TestingInterface.Options (
  ThreatModelNameFilter (..),
  listThreatModelsIngredient,
  listThreatModelsJsonIngredient,
  threatModelNameFilterIngredient,
 )
import Convex.Utils (failOnError)
import Test.Tasty (TestTree, askOption, defaultMainWithIngredients, testGroup)

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
    -- Use 50000 byte limit because secure PingPong paths with datum-hash
    -- spends is large
    opts = modifyTransactionLimits opts0 50_000
    runOpts = runOpts0{mcOptions = opts}
   in
    defaultMainWithIngredients
      (listThreatModelsIngredient : listThreatModelsJsonIngredient : threatModelNameFilterIngredient : streamingIngredients)
      ( askOption $ \(ThreatModelNameFilter tmNameFilter) ->
          tests opts runOpts{threatModelFilter = tmNameFilter}
      )
 where
  config =
    CoverageConfig
      { coverageIndices = [pingPongCovIdx]
      , coverageReport = writeCoverageReport "coverage-report.ignore.txt"
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
