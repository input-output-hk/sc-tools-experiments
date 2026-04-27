module Convex.ThreatModel.All where

import Convex.ThreatModel (ThreatModel)
import Convex.ThreatModel.DatumBloat (datumByteBloatAttack, datumListBloatAttack)
import Convex.ThreatModel.DoubleSatisfaction (doubleSatisfaction)
import Convex.ThreatModel.DuplicateListEntry (duplicateListEntryAttack)
import Convex.ThreatModel.InputDuplication (inputDuplication)
import Convex.ThreatModel.InvalidDatumIndex (invalidDatumIndexAttack)
import Convex.ThreatModel.LargeData (largeDataAttack)
import Convex.ThreatModel.LargeValue (largeValueAttack)
import Convex.ThreatModel.MissingOutputDatum (missingOutputDatumAttack)
import Convex.ThreatModel.MutualExclusion (mutualExclusionAttack)
import Convex.ThreatModel.NegativeInteger (negativeIntegerAttack)
import Convex.ThreatModel.OutputDatumHashMissing (outputDatumHashMissingAttack)
import Convex.ThreatModel.RedeemerAssetSubstitution (redeemerAssetSubstitution)
import Convex.ThreatModel.SelfReferenceInjection (selfReferenceInjection)
import Convex.ThreatModel.SignatoryRemoval (signatoryRemoval)
import Convex.ThreatModel.TimeBoundManipulation (timeBoundManipulation)
import Convex.ThreatModel.UnprotectedScriptOutput (unprotectedScriptOutput)
import Convex.ThreatModel.ValueUnderpayment (valueUnderpaymentAttack)

{- | A list of all the threat models that don't take parameters.
Almost all threat models in this library have versions without parameters, except @TokenForgery@.
-}
allThreatModels :: [ThreatModel ()]
allThreatModels =
  [ datumListBloatAttack
  , datumByteBloatAttack
  , doubleSatisfaction
  , duplicateListEntryAttack
  , inputDuplication
  , invalidDatumIndexAttack
  , largeDataAttack
  , largeValueAttack
  , missingOutputDatumAttack
  , mutualExclusionAttack
  , negativeIntegerAttack
  , outputDatumHashMissingAttack
  , redeemerAssetSubstitution
  , selfReferenceInjection
  , signatoryRemoval
  , timeBoundManipulation
  , unprotectedScriptOutput
  , valueUnderpaymentAttack
  ]
