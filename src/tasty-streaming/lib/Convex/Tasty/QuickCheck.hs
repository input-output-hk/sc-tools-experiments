{- | Drop-in shim for "Test.Tasty.QuickCheck" that captures the source
location of each 'testProperty' definition and propagates it to the
streaming reporter.

Migration is a single-line import change:

@
-- before
import Test.Tasty.QuickCheck (testProperty)

-- after
import Convex.Tasty.QuickCheck (testProperty)
@

Call sites remain byte-for-byte identical. Re-exports everything from
"Test.Tasty.QuickCheck" except 'QC.testProperty', which is replaced by
the location-tracking shim defined here.
-}
module Convex.Tasty.QuickCheck (
  testProperty,
  module Test.Tasty.QuickCheck,
) where

import Convex.Tasty.Streaming.SrcLoc (withSrcLoc)
import GHC.Stack (HasCallStack, withFrozenCallStack)
import Test.Tasty (TestName, TestTree)
import Test.Tasty.QuickCheck hiding (testProperty)
import Test.Tasty.QuickCheck qualified as QC

{- | Like 'QC.testProperty' but captures the call site as a source-location
range that the streaming ingredient will emit alongside the test.
-}
testProperty :: (HasCallStack, Testable a) => TestName -> a -> TestTree
testProperty name prop =
  withFrozenCallStack (withSrcLoc (QC.testProperty name prop))
