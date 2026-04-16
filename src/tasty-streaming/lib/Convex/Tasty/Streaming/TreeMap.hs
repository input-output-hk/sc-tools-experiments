module Convex.Tasty.Streaming.TreeMap (
  buildTestMap,
) where

import Convex.Tasty.Streaming.Types (TestInfo (..))
import Data.IORef
import Data.IntMap.Strict (IntMap)
import Data.IntMap.Strict qualified as IntMap
import Data.Text qualified as Text
import Test.Tasty (TestTree)
import Test.Tasty.Options (OptionSet)
import Test.Tasty.Runners (Ap (..), TreeFold (..), foldTestTree, trivialFold)

{- | Build a mapping from StatusMap integer indices to test metadata.

The indices correspond to the order tests appear during a fold of the TestTree,
which is the same order Tasty uses when building the StatusMap.
-}
buildTestMap :: OptionSet -> TestTree -> IO (IntMap TestInfo)
buildTestMap opts tree = do
  counterRef <- newIORef (0 :: Int)
  let Ap action = foldTestTree (mkFold counterRef) opts tree
  action

mkFold :: IORef Int -> TreeFold (Ap IO (IntMap TestInfo))
mkFold counterRef =
  (trivialFold :: TreeFold (Ap IO (IntMap TestInfo)))
    { foldSingle = \_ name _ -> Ap $ do
        idx <- readIORef counterRef
        modifyIORef' counterRef (+ 1)
        let info =
              TestInfo
                { tiId = idx
                , tiName = Text.pack name
                , tiPath = []
                }
        pure $ IntMap.singleton idx info
    , foldGroup = \_opts groupName children -> Ap $ do
        let Ap childAction = mconcat children
        childMap <- childAction
        let prependGroup ti = ti{tiPath = Text.pack groupName : tiPath ti}
        pure $ fmap prependGroup childMap
    , foldResource = \_ _ k ->
        k (error "Convex.Tasty.Streaming.TreeMap: resource not available during fold")
    }
