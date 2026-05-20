{- | Drop-in shim for "Test.Tasty.HUnit" that captures the source location
of each 'testCase' definition and propagates it to the streaming reporter.

Migration is a single-line import change:

@
-- before
import Test.Tasty.HUnit (testCase)

-- after
import Convex.Tasty.HUnit (testCase)
@

Call sites remain byte-for-byte identical. Re-exports everything from
"Test.Tasty.HUnit" except 'HUnit.testCase', which is replaced by the
location-tracking shim defined here.
-}
module Convex.Tasty.HUnit (
  testCase,
  module Test.Tasty.HUnit,
) where

import Convex.Tasty.Streaming.SrcLoc (withSrcLoc)
import GHC.Stack (withFrozenCallStack)
import Test.Tasty (TestName, TestTree)
import Test.Tasty.HUnit hiding (testCase)
import Test.Tasty.HUnit qualified as HUnit

{- | Like 'HUnit.testCase' but captures the call site as a source-location
range that the streaming ingredient will emit alongside the test.
-}
testCase :: (HasCallStack) => TestName -> Assertion -> TestTree
testCase name body = withFrozenCallStack (withSrcLoc (HUnit.testCase name body))
