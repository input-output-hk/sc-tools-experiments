{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}

-- | Coverage data extraction module for mockchain
module Convex.MockChain.Coverage (

) where

import Cardano.Api (ConwayEra)
import Convex.MockChain.Defaults qualified as Defaults
import Convex.NodeParams (NodeParams)
import Data.IORef (IORef)
import PlutusTx.Coverage (CoverageData)
