module Convex.TestingInterface.Options (
  ThreatModelNameFilter (..),
  threatModelNameFilterIngredient,
  ListThreatModels (..),
  listThreatModelsIngredient,
  ListThreatModelsJson (..),
  listThreatModelsJsonIngredient,
) where

import Convex.ThreatModel.All (allThreatModelsNames)
import Data.Aeson ((.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.ByteString.Lazy.Char8 qualified as LBS
import Data.Proxy (Proxy (..))
import Data.Tagged (Tagged (..))
import Data.Typeable (Typeable)
import System.Exit (exitSuccess)
import System.IO (BufferMode (..), hSetBuffering, stdout)
import Test.Tasty.Ingredients (Ingredient (..))
import Test.Tasty.Options (IsOption (..), OptionDescription (..), lookupOption, mkFlagCLParser, safeRead)

newtype ThreatModelNameFilter = ThreatModelNameFilter [String]
  deriving (Eq, Ord, Typeable)

instance Monoid ThreatModelNameFilter where
  mempty = ThreatModelNameFilter []

instance Semigroup ThreatModelNameFilter where
  ThreatModelNameFilter a <> ThreatModelNameFilter b = ThreatModelNameFilter (a <> b)

instance IsOption ThreatModelNameFilter where
  defaultValue = ThreatModelNameFilter []
  parseValue raw = Just (ThreatModelNameFilter (parseThreatModelNames raw))
   where
    parseThreatModelNames s =
      case s of
        "" -> []
        _ -> map trim (splitOn ',' s)
    splitOn _ [] = []
    splitOn delim s = case break (== delim) s of
      (a, []) -> [a]
      (a, _ : rest) -> a : splitOn delim rest
    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse
  optionName = Tagged "threat-model-name"
  optionHelp = Tagged "Run only threat models whose names start with these values (comma-separated for multiple; case-sensitive); expected vulnerabilities are unaffected"

threatModelNameFilterIngredient :: Ingredient
threatModelNameFilterIngredient =
  TestManager
    [Option (Proxy :: Proxy ThreatModelNameFilter)]
    (\_ _ -> Nothing)

newtype ListThreatModels = ListThreatModels Bool
  deriving (Eq, Ord, Typeable)

instance IsOption ListThreatModels where
  defaultValue = ListThreatModels False
  parseValue = Just . ListThreatModels . (== "True")
  optionName = Tagged "list-threat-models"
  optionHelp = Tagged "List all available threat models and exit (does not run tests)"
  optionCLParser = mkFlagCLParser mempty (ListThreatModels True)

listThreatModelsIngredient :: Ingredient
listThreatModelsIngredient =
  TestManager
    [Option (Proxy :: Proxy ListThreatModels)]
    $ \opts _ ->
      let ListThreatModels shouldList = lookupOption opts
       in if not shouldList
            then Nothing
            else Just $ do
              mapM_ putStrLn allThreatModelsNames
              exitSuccess

newtype ListThreatModelsJson = ListThreatModelsJson Bool
  deriving (Eq, Ord, Typeable)

instance IsOption ListThreatModelsJson where
  defaultValue = ListThreatModelsJson False
  parseValue = fmap ListThreatModelsJson . safeRead
  optionName = Tagged "list-threat-models-json"
  optionHelp = Tagged "List all available threat models as JSON and exit (does not run tests)"
  optionCLParser = mkFlagCLParser mempty (ListThreatModelsJson True)

listThreatModelsJsonIngredient :: Ingredient
listThreatModelsJsonIngredient =
  TestManager
    [Option (Proxy :: Proxy ListThreatModelsJson)]
    $ \opts _ ->
      let ListThreatModelsJson shouldList = lookupOption opts
       in if not shouldList
            then Nothing
            else Just $ do
              hSetBuffering stdout LineBuffering
              LBS.putStrLn $ Aeson.encode $ Aeson.object [Key.fromString "threatModels" .= allThreatModelsNames]
              exitSuccess
