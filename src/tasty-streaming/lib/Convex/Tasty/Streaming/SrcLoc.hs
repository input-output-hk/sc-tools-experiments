{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

{- | Source-location tracking for tests streamed by the Tasty ingredient.

This module provides:

* 'SrcLocRange' — a JSON-friendly source range type matching the shape used
  elsewhere in this repo (file, startLine, startCol, endLine, endCol).
* 'SrcLocOpt' — a Tasty 'IsOption' instance carrying an optional location.
  Tasty propagates options from 'localOption' down into every child leaf
  through 'PlusTestOptions' nodes, so we use it as a side channel between
  the user-facing API boundary and the streaming ingredient.
* 'withSrcLoc' — a 'HasCallStack'-instrumented combinator that captures the
  immediate caller's source location and attaches it to a 'TestTree' via
  'localOption'.
* 'PackageRootOpt' — a Tasty 'IsOption' carrying the optional absolute path
  to the cabal package containing the user's @Main.hs@. Populated by
  'Convex.Tasty.Streaming.defaultMainStreaming' from the top of the
  'HasCallStack' call-stack and consumed by the streaming reporter / list
  ingredient to populate the @packageRoot@ field on @SuiteStarted@.
* 'callerPackageRoot' / 'findPackageRootFromFile' — helpers that walk up
  from a source file to the nearest enclosing @.cabal@ directory.

This is intentionally kept separate from any specific test provider
('Test.Tasty.HUnit', 'Test.Tasty.QuickCheck', etc.) so that user-facing
shims and library-internal wrappers (e.g. @propRunActions@) can share the
same machinery.
-}
module Convex.Tasty.Streaming.SrcLoc (
  SrcLocRange (..),
  SrcLocOpt (..),
  withSrcLoc,
  currentSrcLocRange,
  fromGhcSrcLoc,
  PackageRootOpt (..),
  callerPackageRoot,
  findPackageRootFromFile,
  SrcLocRanges (..),
  groupRanges,
  ungroupRanges,
) where

import Control.Exception (IOException, catch)
import Data.Aeson (FromJSON (..), ToJSON (..), object, withObject, (.:), (.=))
import Data.List (groupBy, isSuffixOf, zip4)
import Data.Tagged (Tagged (..))
import Data.Text (Text)
import Data.Text qualified as Text
import GHC.Generics (Generic)
import GHC.Stack (
  CallStack,
  HasCallStack,
  SrcLoc,
  callStack,
  getCallStack,
  srcLocEndCol,
  srcLocEndLine,
  srcLocFile,
  srcLocPackage,
  srcLocStartCol,
  srcLocStartLine,
  withFrozenCallStack,
 )
import System.Directory (
  canonicalizePath,
  doesDirectoryExist,
  doesFileExist,
  getCurrentDirectory,
  listDirectory,
 )
import System.FilePath (isAbsolute, takeDirectory, (</>))
import Test.Tasty (TestTree, localOption)
import Test.Tasty.Options (IsOption (..))

{- | A source-location range, semantically equivalent to the LSP/editor
@file:startLine:startCol-endLine:endCol@ shape.

The end position is typically one past the end of the function-name token
(e.g. just past @testCase@), not the end of the user's full expression —
'HasCallStack' does not give us expression spans.
-}
data SrcLocRange = SrcLocRange
  { slrFile :: !Text
  , slrStartLine :: !Int
  , slrStartCol :: !Int
  , slrEndLine :: !Int
  , slrEndCol :: !Int
  }
  deriving (Eq, Show, Generic)

instance ToJSON SrcLocRange where
  toJSON SrcLocRange{..} =
    object
      [ "file" .= slrFile
      , "startLine" .= slrStartLine
      , "startCol" .= slrStartCol
      , "endLine" .= slrEndLine
      , "endCol" .= slrEndCol
      ]

instance FromJSON SrcLocRange where
  parseJSON = withObject "SrcLocRange" $ \o ->
    SrcLocRange
      <$> o .: "file"
      <*> o .: "startLine"
      <*> o .: "startCol"
      <*> o .: "endLine"
      <*> o .: "endCol"

{- | Internal Tasty option carrying the source-location of a test definition.

Not user-settable from the command line; it is only ever populated via
'withSrcLoc' (or, transitively, the @Convex.Tasty.HUnit@ /
@Convex.Tasty.QuickCheck@ shims).
-}
newtype SrcLocOpt = SrcLocOpt (Maybe SrcLocRange)
  deriving (Eq, Show)

instance IsOption SrcLocOpt where
  defaultValue = SrcLocOpt Nothing
  parseValue = const Nothing
  optionName = Tagged "internal-srcloc"
  optionHelp = Tagged "Internal: source location of the test definition"

{- | Capture the immediate caller's location from the implicit 'CallStack'.

Returns 'Nothing' if the call stack is empty (e.g. when called from a
context without a 'HasCallStack' chain reaching a real call site).
-}
currentSrcLocRange :: (HasCallStack) => Maybe SrcLocRange
currentSrcLocRange = topOfStack callStack
 where
  topOfStack :: CallStack -> Maybe SrcLocRange
  topOfStack cs = case getCallStack cs of
    ((_, loc) : _) -> Just (fromGhcSrcLoc loc)
    _ -> Nothing

-- | Convert a GHC 'SrcLoc' to our JSON-friendly 'SrcLocRange'.
fromGhcSrcLoc :: SrcLoc -> SrcLocRange
fromGhcSrcLoc loc =
  SrcLocRange
    { slrFile = Text.pack (srcLocFile loc)
    , slrStartLine = srcLocStartLine loc
    , slrStartCol = srcLocStartCol loc
    , slrEndLine = srcLocEndLine loc
    , slrEndCol = srcLocEndCol loc
    }

{- | Annotate a 'TestTree' with the caller's source location.

Use 'withFrozenCallStack' at the call site if you are writing a shim that
delegates to this combinator, so that the captured location reflects the
shim's caller rather than the shim itself.
-}
withSrcLoc :: (HasCallStack) => TestTree -> TestTree
withSrcLoc = withFrozenCallStack (localOption (SrcLocOpt currentSrcLocRange))

{- | Internal Tasty option carrying the absolute path of the cabal package
that contains the user's @Main.hs@ test entry point.

Populated by 'Convex.Tasty.Streaming.defaultMainStreaming' from the top of
the 'HasCallStack' call-stack (which points at the user's @Main.hs@) by
walking up the directory tree until a @.cabal@ file is found. Consumed by
the streaming JSON reporter and the @--list-tests-json@ ingredient to
populate the @packageRoot@ field of the @SuiteStarted@ event.

Not user-settable from the command line. 'defaultValue' is
@PackageRootOpt Nothing@; when no @.cabal@ file can be located above the
caller, the field is omitted from JSON output.
-}
newtype PackageRootOpt = PackageRootOpt (Maybe Text)
  deriving (Eq, Show)

instance IsOption PackageRootOpt where
  defaultValue = PackageRootOpt Nothing
  parseValue = const Nothing
  optionName = Tagged "internal-package-root"
  optionHelp = Tagged "Internal: cabal package root captured from the call site of defaultMainStreaming"

{- | Resolve the cabal package containing the given source file.

The input is typically a 'GHC.Stack.srcLocFile' value: an absolute path
when GHC was run from the package directory, but in practice (under
@cabal run@ and @cabal test@) a path /relative to the package directory/
such as @"test/Spec.hs"@. The current working directory of a @cabal run@
process is the workspace root (the directory containing
@cabal.project@), __not__ the package directory.

Resolution strategy:

* If the path is absolute, walk up its parent directories until a
  directory containing any @.cabal@ file is found. Return that directory.
* If the path is relative, recursively scan downward from the current
  working directory (bounded by 'searchDepth') for any directory that
  both contains a @.cabal@ file and contains the relative path on disk
  (i.e. @D \</\> relativePath@ exists). The first match in a
  depth-first traversal wins. This copes with the common monorepo
  layout where packages live under @src/*\/@ relative to the workspace
  root.

The search is bounded to avoid exploring the entire filesystem in
pathological setups. Hidden directories (those starting with @.@),
@dist-newstyle@, and common build/dependency directories are skipped
to keep the cost predictable.

Returns 'Nothing' when no match is found.

'IOException's from filesystem operations are caught and treated as
empty/absent so that permission errors on unrelated subtrees do not
abort the walk.
-}
findPackageRootFromFile :: FilePath -> IO (Maybe FilePath)
findPackageRootFromFile path
  | isAbsolute path = do
      absPath <- canonicalizePath path
      walkUpAbsolute (takeDirectory absPath)
  | otherwise = do
      cwd <- getCurrentDirectory
      searchDown searchDepth cwd path
 where
  -- Maximum recursion depth for the downward search. The known layouts in
  -- this repo place package roots at depth <= 3 (e.g. @src/use-cases/@);
  -- we allow a bit more to be tolerant of deeper monorepo shapes.
  searchDepth :: Int
  searchDepth = 5

  -- Walk up from an absolute starting directory until we find a directory
  -- containing a .cabal file.
  walkUpAbsolute dir = do
    hasCabal <- dirHasCabalFile dir
    if hasCabal
      then pure (Just dir)
      else
        let parent = takeDirectory dir
         in if parent == dir
              then pure Nothing
              else walkUpAbsolute parent

  -- Depth-bounded depth-first search rooted at 'dir' for a package
  -- directory whose tree contains 'relPath'.
  searchDown :: Int -> FilePath -> FilePath -> IO (Maybe FilePath)
  searchDown depth dir relPath = do
    -- Try 'dir' itself first.
    selfMatch <- isPackageWithFile dir relPath
    case selfMatch of
      Just _ -> pure selfMatch
      Nothing
        | depth <= 0 -> pure Nothing
        | otherwise -> do
            entries <-
              listDirectory dir
                `catch` \(_ :: IOException) -> pure []
            let visit = filter (not . shouldSkip) entries
                pickFirst [] = pure Nothing
                pickFirst (e : es) = do
                  let sub = dir </> e
                  isDir <- doesDirectoryExist sub
                  if isDir
                    then do
                      m <- searchDown (depth - 1) sub relPath
                      case m of
                        Just _ -> pure m
                        Nothing -> pickFirst es
                    else pickFirst es
            pickFirst visit

  isPackageWithFile dir relPath = do
    hasCabal <- dirHasCabalFile dir
    if hasCabal
      then do
        exists <- doesFileExist (dir </> relPath)
        pure (if exists then Just dir else Nothing)
      else pure Nothing

  dirHasCabalFile dir = do
    entries <-
      listDirectory dir
        `catch` \(_ :: IOException) -> pure []
    pure (any (".cabal" `isSuffixOf`) entries)

  -- Skip hidden directories and well-known build/dependency roots so the
  -- search does not descend into @dist-newstyle@, @node_modules@, etc.
  shouldSkip ('.' : _) = True
  shouldSkip "dist-newstyle" = True
  shouldSkip "dist" = True
  shouldSkip "node_modules" = True
  shouldSkip _ = False

{- | Resolve the caller's package root from a 'HasCallStack' constraint.

Returns the absolute path of the directory containing the package's
@.cabal@ file, or 'Nothing' when no match can be located.

The strategy combines two signals from the top of the call stack:

* 'srcLocPackage' — the GHC-internal package identifier of the calling
  module, e.g.
  @"convex-testing-interface-0.1.0.0-inplace-convex-testing-interface-test"@.
  The first @"-<digit>"@ token of that string marks the start of the
  package version; everything before it is the package name.
* 'srcLocFile' — the GHC-recorded source file path, typically
  package-relative (e.g. @"test/Spec.hs"@).

If a package name can be extracted, we search downward from the current
working directory for a directory containing both a matching
@\<name\>.cabal@ file /and/ the relative source file. If the package
name is unavailable or no match is found, we fall back to the
file-based search in 'findPackageRootFromFile'.

Intended to be invoked at the very top of a test entry point (e.g. from
'Convex.Tasty.Streaming.defaultMainStreaming') so that the captured
location corresponds to the user's @Main.hs@.
-}
callerPackageRoot :: (HasCallStack) => IO (Maybe FilePath)
callerPackageRoot = case getCallStack callStack of
  ((_, loc) : _) -> do
    let pkgName = extractPackageName (srcLocPackage loc)
        file = srcLocFile loc
    case pkgName of
      Just name -> do
        cwd <- getCurrentDirectory
        mFound <- findPackageByName cwd name file
        case mFound of
          Just root -> pure (Just root)
          Nothing -> findPackageRootFromFile file
      Nothing -> findPackageRootFromFile file
  _ -> pure Nothing

{- | Extract a cabal package name from a GHC package identifier string.

GHC encodes the package id as @\<name\>-\<version\>[-\<extra\>]@. The
version always starts with a digit, so we take everything before the
first @"-<digit>"@ separator. Returns 'Nothing' if no such separator is
found.

>>> extractPackageName "convex-testing-interface-0.1.0.0-inplace-..."
Just "convex-testing-interface"
>>> extractPackageName "base-4.18.2.1"
Just "base"
>>> extractPackageName ""
Nothing
-}
extractPackageName :: String -> Maybe String
extractPackageName = go []
 where
  go acc ('-' : c : rest)
    | c >= '0' && c <= '9' = Just (reverse acc)
    | otherwise = go (c : '-' : acc) rest
  go acc (c : rest) = go (c : acc) rest
  go _ [] = Nothing

{- | Recursive depth-bounded search rooted at 'startDir' for a directory
containing both a @\<pkgName\>.cabal@ file and the relative source
'relFile'. Returns the directory on success.
-}
findPackageByName :: FilePath -> String -> FilePath -> IO (Maybe FilePath)
findPackageByName startDir pkgName relFile = go searchDepth startDir
 where
  searchDepth :: Int
  searchDepth = 6
  cabalBaseName = pkgName <> ".cabal"

  go depth dir = do
    -- Check this directory first.
    hasCabal <- doesFileExist (dir </> cabalBaseName)
    let relAbsolute = isAbsolute relFile
    selfMatch <-
      if hasCabal
        then
          if relAbsolute
            then pure (Just dir)
            else do
              exists <- doesFileExist (dir </> relFile)
              pure (if exists then Just dir else Nothing)
        else pure Nothing
    case selfMatch of
      Just _ -> pure selfMatch
      Nothing
        | depth <= 0 -> pure Nothing
        | otherwise -> do
            entries <-
              listDirectory dir
                `catch` \(_ :: IOException) -> pure []
            let visit = filter (not . shouldSkip) entries
                pickFirst [] = pure Nothing
                pickFirst (e : es) = do
                  let sub = dir </> e
                  isDir <- doesDirectoryExist sub
                  if isDir
                    then do
                      m <- go (depth - 1) sub
                      case m of
                        Just _ -> pure m
                        Nothing -> pickFirst es
                    else pickFirst es
            pickFirst visit

  shouldSkip ('.' : _) = True
  shouldSkip "dist-newstyle" = True
  shouldSkip "dist" = True
  shouldSkip "node_modules" = True
  shouldSkip _ = False

-- | Many ranges in one file, for more efficient JSON serialization
data SrcLocRanges = SrcLocRanges
  { slrsFile :: !Text
  , slrsStartLines :: [Int]
  , slrsStartCols :: [Int]
  , slrsEndLines :: [Int]
  , slrsEndCols :: [Int]
  }
  deriving (Eq, Show, Generic)

instance ToJSON SrcLocRanges where
  toJSON SrcLocRanges{..} =
    object
      [ "file" .= slrsFile
      , "startLines" .= slrsStartLines
      , "startCols" .= slrsStartCols
      , "endLines" .= slrsEndLines
      , "endCols" .= slrsEndCols
      ]

instance FromJSON SrcLocRanges where
  parseJSON = withObject "SrcLocRanges" $ \o ->
    SrcLocRanges
      <$> o .: "file"
      <*> o .: "startLines"
      <*> o .: "startCols"
      <*> o .: "endLines"
      <*> o .: "endCols"

groupRanges :: [SrcLocRange] -> [SrcLocRanges]
groupRanges = map toRanges . groupBy (\a b -> slrFile a == slrFile b)
 where
  toRanges :: [SrcLocRange] -> SrcLocRanges
  toRanges rs =
    SrcLocRanges
      { slrsFile = slrFile (rs !! 0)
      , slrsStartLines = map slrStartLine rs
      , slrsStartCols = map slrStartCol rs
      , slrsEndLines = map slrEndLine rs
      , slrsEndCols = map slrEndCol rs
      }

ungroupRanges :: [SrcLocRanges] -> [SrcLocRange]
ungroupRanges = concatMap go
 where
  go SrcLocRanges{..} =
    [ SrcLocRange slrsFile sl sc el ec
    | (sl, sc, el, ec) <- zip4 slrsStartLines slrsStartCols slrsEndLines slrsEndCols
    ]
