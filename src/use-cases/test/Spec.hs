import Specs.VestingSpec qualified
import Test.Tasty (
  TestTree,
  defaultMain,
  testGroup,
 )

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "vesting tests"
    [ Specs.VestingSpec.unitTests
    , Specs.VestingSpec.propBasedTests
    ]
