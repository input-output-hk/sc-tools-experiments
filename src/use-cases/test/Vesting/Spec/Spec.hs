import Vesting.Spec.Prop qualified
import Vesting.Spec.Unit qualified

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
    [ Vesting.Spec.Unit.unitTests
    , Vesting.Spec.Prop.propBasedTests
    ]
