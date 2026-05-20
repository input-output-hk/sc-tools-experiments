{-# LANGUAGE NamedFieldPuns #-}

{- | Tests for source-location tracking in the streaming Tasty ingredient.

Covers the integration between 'Convex.Tasty.Streaming.SrcLoc.withSrcLoc'
(and the user-facing shims 'Convex.Tasty.HUnit.testCase' /
'Convex.Tasty.QuickCheck.testProperty') and the 'TestInfo' values produced
by 'Convex.Tasty.Streaming.TreeMap.buildTestMap'.
-}
module Convex.Tasty.SrcLocSpec (tests) where

import Convex.Tasty.HUnit (Assertion, assertBool, assertEqual, assertFailure, testCase, (@?=))
import Convex.Tasty.HUnit qualified as ConvexHU
import Convex.Tasty.QuickCheck qualified as ConvexQC
import Convex.Tasty.Streaming.SrcLoc (
  SrcLocRange (..),
  callerPackageRoot,
  findPackageRootFromFile,
  withSrcLoc,
 )
import Convex.Tasty.Streaming.TreeMap (buildTestMap)
import Convex.Tasty.Streaming.Types (Event (..), TestInfo (..))
import Data.Aeson qualified as Aeson
import Data.Aeson.KeyMap qualified as KeyMap
import Data.IntMap.Strict qualified as IntMap
import Data.List (isSuffixOf, sort)
import Data.Maybe (isJust, isNothing)
import Data.Text qualified as Text
import GHC.Stack (HasCallStack)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit qualified as HUnit
import Test.Tasty.QuickCheck qualified as QC

tests :: TestTree
tests =
  testGroup
    "SrcLoc"
    [ testCase "shim'd leaf has a location" shimmedLeafHasLocation
    , testCase "upstream leaf has no location" upstreamLeafHasNoLocation
    , testCase "interop: shim leaf + upstream leaf in same group" mixedTreeInterop
    , testCase "withSrcLoc propagates down to children" withSrcLocPropagates
    , testCase "round-trip with srcLoc" roundTripWithSrcLoc
    , testCase "round-trip without srcLoc (key absent)" roundTripWithoutSrcLoc
    , testCase "SuiteStarted round-trip with packageRoot" suiteStartedWithPackageRoot
    , testCase "SuiteStarted without packageRoot (key absent)" suiteStartedWithoutPackageRoot
    , testCase "callerPackageRoot resolves to convex-tasty-streaming" callerPackageRootResolvesToThisPackage
    , testCase "findPackageRootFromFile finds convex-tasty-streaming" findPackageRootFromFileFindsThisPackage
    ]

{- | Helper: build the test map for a tree using an empty 'OptionSet'.

 'buildTestMap' uses 'lookupOption' to pull each individual option
 (including 'SrcLocOpt') out, falling back to its declared
 'defaultValue' when absent from the OptionSet. So an empty starting
 set is exactly what we want when exercising 'withSrcLoc' (which
 attaches the option to the tree itself via 'localOption').
-}
buildMap :: TestTree -> IO [TestInfo]
buildMap tree = IntMap.elems <$> buildTestMap mempty tree

-- ---------------------------------------------------------------------------
-- 1. Leaf with our shim has a location
-- ---------------------------------------------------------------------------

shimmedLeafHasLocation :: Assertion
shimmedLeafHasLocation = do
  let tree = ConvexHU.testCase "shim case" (pure ())
  [info] <- buildMap tree
  case tiSrcLoc info of
    Nothing ->
      assertFailure "Expected Just SrcLocRange for shim'd testCase, got Nothing"
    Just SrcLocRange{slrFile} -> do
      -- Must point at this very file (the call site).
      assertBool
        ("Expected slrFile to mention SrcLocSpec.hs, got: " <> Text.unpack slrFile)
        ("SrcLocSpec.hs" `Text.isSuffixOf` slrFile)

-- ---------------------------------------------------------------------------
-- 2. Leaf with upstream tasty-hunit has no location
-- ---------------------------------------------------------------------------

upstreamLeafHasNoLocation :: Assertion
upstreamLeafHasNoLocation = do
  let tree = HUnit.testCase "upstream case" (pure ())
  [info] <- buildMap tree
  assertEqual
    "Upstream testCase should have no source-location"
    Nothing
    (tiSrcLoc info)

-- ---------------------------------------------------------------------------
-- 3. Interop: a shim'd leaf and an upstream leaf in the same group
-- ---------------------------------------------------------------------------

mixedTreeInterop :: Assertion
mixedTreeInterop = do
  let tree =
        testGroup
          "mixed"
          [ ConvexHU.testCase "shim" (pure ())
          , HUnit.testCase "upstream" (pure ())
          , ConvexQC.testProperty "shim prop" (QC.property True)
          ]
  infos <- buildMap tree
  length infos @?= 3
  let byName = [(tiName i, tiSrcLoc i) | i <- infos]
      shim = lookup "shim" byName
      upstream = lookup "upstream" byName
      shimProp = lookup "shim prop" byName
  -- Group path is preserved on every child.
  assertEqual
    "group path"
    [["mixed"], ["mixed"], ["mixed"]]
    (sort [tiPath i | i <- infos])
  case shim of
    Just (Just _) -> pure ()
    other -> assertFailure ("Expected shim leaf to have Just loc, got: " <> show other)
  case shimProp of
    Just (Just _) -> pure ()
    other -> assertFailure ("Expected shim'd property to have Just loc, got: " <> show other)
  case upstream of
    Just Nothing -> pure ()
    other -> assertFailure ("Expected upstream leaf to have Nothing loc, got: " <> show other)

-- ---------------------------------------------------------------------------
-- 4. 'withSrcLoc' applied to an upstream subtree propagates to all children
-- ---------------------------------------------------------------------------
-- This documents the (potentially surprising) behaviour: 'localOption'
-- propagates down through 'PlusTestOptions' nodes, so wrapping a group
-- with 'withSrcLoc' implicitly tags every unannotated child leaf.

withSrcLocPropagates :: Assertion
withSrcLocPropagates = do
  let tree =
        withSrcLoc $
          testGroup
            "group"
            [ HUnit.testCase "a" (pure ())
            , HUnit.testCase "b" (pure ())
            ]
  infos <- buildMap tree
  length infos @?= 2
  -- Both children must inherit the (single) outer location.
  assertBool
    "Both upstream leaves should have inherited a location from withSrcLoc"
    (all (isJust . tiSrcLoc) infos)
  -- Sanity check: without the wrapper, the same tree has Nothing on both leaves.
  let bareTree =
        testGroup
          "group"
          [ HUnit.testCase "a" (pure ())
          , HUnit.testCase "b" (pure ())
          ]
  bareInfos <- buildMap bareTree
  assertBool
    "Without withSrcLoc, upstream leaves should have no location"
    (all (isNothing . tiSrcLoc) bareInfos)

-- ---------------------------------------------------------------------------
-- 5. (Originally: propRunActions populates locations on all sub-tests.)
--   See note in the migration plan: this assertion lives in
--   'convex-testing-interface' tests because importing 'propRunActions'
--   here would create a circular package dependency.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 6. NDJSON round-trip
-- ---------------------------------------------------------------------------

roundTripWithSrcLoc :: Assertion
roundTripWithSrcLoc = do
  let loc =
        SrcLocRange
          { slrFile = "src/Foo.hs"
          , slrStartLine = 10
          , slrStartCol = 5
          , slrEndLine = 10
          , slrEndCol = 13
          }
      info =
        TestInfo
          { tiId = 0
          , tiName = "demo"
          , tiPath = ["group"]
          , tiSrcLoc = Just loc
          }
      encoded = Aeson.encode info
  -- Sanity: the encoded JSON contains the srcLoc field.
  case Aeson.eitherDecode encoded of
    Left err -> assertFailure $ "decode failed: " <> err
    Right info' -> info' @?= info

roundTripWithoutSrcLoc :: Assertion
roundTripWithoutSrcLoc = do
  let info =
        TestInfo
          { tiId = 1
          , tiName = "demo"
          , tiPath = []
          , tiSrcLoc = Nothing
          }
      encoded = Aeson.encode info
  -- The "srcLoc" key must be absent (NOT "srcLoc": null).
  case Aeson.decode encoded :: Maybe Aeson.Value of
    Just (Aeson.Object o) ->
      assertBool
        "Encoded JSON must omit srcLoc key when tiSrcLoc is Nothing"
        (not (KeyMap.member "srcLoc" o))
    other ->
      assertFailure $ "Expected JSON object, got: " <> show other
  -- And decoding round-trips.
  case Aeson.eitherDecode encoded of
    Left err -> assertFailure $ "decode failed: " <> err
    Right info' -> info' @?= info

-- ---------------------------------------------------------------------------
-- 7. SuiteStarted round-trip with packageRoot
-- ---------------------------------------------------------------------------

suiteStartedWithPackageRoot :: Assertion
suiteStartedWithPackageRoot = do
  let info =
        TestInfo
          { tiId = 0
          , tiName = "demo"
          , tiPath = ["group"]
          , tiSrcLoc = Nothing
          }
      evt = SuiteStarted (Just "/abs/path/to/pkg") [info]
      encoded = Aeson.encode evt
  -- The "packageRoot" key must be present at the top level.
  case Aeson.decode encoded :: Maybe Aeson.Value of
    Just (Aeson.Object o) ->
      assertBool
        "Encoded SuiteStarted must include packageRoot key when esPackageRoot is Just"
        (KeyMap.member "packageRoot" o)
    other ->
      assertFailure $ "Expected JSON object, got: " <> show other
  -- Round-trip equality.
  case Aeson.eitherDecode encoded of
    Left err -> assertFailure $ "decode failed: " <> err
    Right evt' -> evt' @?= evt

-- ---------------------------------------------------------------------------
-- 8. SuiteStarted without packageRoot (key absent from JSON, not null)
-- ---------------------------------------------------------------------------

suiteStartedWithoutPackageRoot :: Assertion
suiteStartedWithoutPackageRoot = do
  let info =
        TestInfo
          { tiId = 0
          , tiName = "demo"
          , tiPath = []
          , tiSrcLoc = Nothing
          }
      evt = SuiteStarted Nothing [info]
      encoded = Aeson.encode evt
  -- The "packageRoot" key must be absent (NOT "packageRoot": null).
  case Aeson.decode encoded :: Maybe Aeson.Value of
    Just (Aeson.Object o) ->
      assertBool
        "Encoded SuiteStarted must omit packageRoot key when esPackageRoot is Nothing"
        (not (KeyMap.member "packageRoot" o))
    other ->
      assertFailure $ "Expected JSON object, got: " <> show other
  -- Round-trip equality.
  case Aeson.eitherDecode encoded of
    Left err -> assertFailure $ "decode failed: " <> err
    Right evt' -> evt' @?= evt

-- ---------------------------------------------------------------------------
-- 9. callerPackageRoot end-to-end: when invoked from inside this test
--    suite, it must resolve to the package directory containing the
--    convex-tasty-streaming.cabal file (this same package).
-- ---------------------------------------------------------------------------
--
-- 'HasCallStack' is propagated through the helper 'callHere' below so that
-- the top stack frame inside 'callerPackageRoot' points at /this/ source
-- file; the walk-up then locates 'convex-tasty-streaming.cabal'.

callHere :: (HasCallStack) => IO (Maybe FilePath)
callHere = callerPackageRoot

callerPackageRootResolvesToThisPackage :: Assertion
callerPackageRootResolvesToThisPackage = do
  mRoot <- callHere
  case mRoot of
    Nothing ->
      assertFailure "callerPackageRoot returned Nothing; expected the convex-tasty-streaming package directory"
    Just root ->
      assertBool
        ( "Expected callerPackageRoot to end with 'src/tasty-streaming', got: "
            <> root
        )
        ("src/tasty-streaming" `isSuffixOf` root)

-- ---------------------------------------------------------------------------
-- 10. findPackageRootFromFile end-to-end: given a known package-relative
--     path to a file inside convex-tasty-streaming, the helper must return
--     the package directory.
-- ---------------------------------------------------------------------------

findPackageRootFromFileFindsThisPackage :: Assertion
findPackageRootFromFileFindsThisPackage = do
  -- Use a known package-relative path that exists inside
  -- convex-tasty-streaming. (Using an absolute path would short-circuit
  -- straight into the file-based walk-up branch, which is not what we
  -- want to exercise here; the relative branch is the one that runs in
  -- the wild under 'cabal run'.)
  mRoot <- findPackageRootFromFile "test/Convex/Tasty/SrcLocSpec.hs"
  case mRoot of
    Nothing ->
      assertFailure
        "findPackageRootFromFile returned Nothing; expected the convex-tasty-streaming package directory"
    Just root ->
      assertBool
        ( "Expected findPackageRootFromFile to end with 'src/tasty-streaming', got: "
            <> root
        )
        ("src/tasty-streaming" `isSuffixOf` root)
