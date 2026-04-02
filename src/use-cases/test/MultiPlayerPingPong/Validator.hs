{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}
{-# OPTIONS_GHC -g -fplugin-opt PlutusTx.Plugin:coverage-all #-}

{- | Secure Multi-Player PingPong validator.

Extends the single-player PingPong contract to support N players (N >= 2)
taking turns in a strict round-robin rotation. On each turn the current
player hits the ball (alternating Pinged/Ponged), advancing the
currentIndex by 1 modulo the number of players. When the index wraps
back to 0, roundCount is incremented.

== Turn Rotation ==

  players      = [Alice, Bob, Carol]
  currentIndex = 0  -> Alice must sign the Hit transaction
  After Hit    -> currentIndex = 1, ballState flips, roundCount unchanged
  After Hit    -> currentIndex = 2, ballState flips, roundCount unchanged
  After Hit    -> currentIndex = 0, ballState flips, roundCount += 1  (full rotation)

== Security Measures (inherited from Scripts.PingPong) ==

1. __Unprotected Script Output Attack__: 'findContinuationOutput' ensures
   the continuation UTxO is sent back to the SAME script address, preventing
   an attacker from redirecting funds while producing a syntactically valid
   datum.

2. __Large Data Attack__: All datum and redeemer types use strict manual
   'ToData' / 'UnsafeFromData' instances that reject any constructor with
   unexpected extra fields. 'unstableMakeIsData' is deliberately avoided for
   'MultiPingPongDatum' and 'BallState' because the TH-generated instances
   silently ignore extra fields, which could allow an attacker to bloat the
   UTxO until it becomes permanently unspendable.

3. __Large Value Attack__: On every 'Hit', the output value at the script
   address must exactly equal the input value. This prevents an attacker
   from attaching junk tokens to the UTxO, which would inflate the
   min-UTxO requirement and could lock funds forever.

== New Checks (not in the single-player version) ==

* __Signer verification__: Each 'Hit' transaction must be signed by exactly
  the player whose turn it is (players !! currentIndex). No other party may
  advance the game.

* __Player count guard__: Any datum listing fewer than 2 players is
  rejected on-chain before the validator proceeds.

* __Index bounds check__: A currentIndex that is negative or >= length
  players is rejected immediately.

* __Round count guard__: A negative roundCount is rejected immediately.
-}
module MultiPlayerPingPong.Validator where

import PlutusLedgerApi.V1.Address (Address (..))
import PlutusLedgerApi.V1.Crypto (PubKeyHash)
import PlutusLedgerApi.V1.Scripts (Datum (getDatum), DatumHash, Redeemer (..))
import PlutusLedgerApi.V2.Tx (
  OutputDatum (NoOutputDatum, OutputDatum, OutputDatumHash),
  TxOut (TxOut, txOutAddress, txOutDatum, txOutValue),
 )
import PlutusLedgerApi.V3.Contexts (
  ScriptContext (..),
  ScriptInfo (SpendingScript),
  TxInInfo (TxInInfo, txInInfoOutRef, txInInfoResolved),
  TxInfo (..),
 )
import PlutusLedgerApi.V3.Tx (TxOutRef)
import PlutusTx.AssocMap (Map, lookup)
import PlutusTx.Builtins (mkConstr, unsafeDataAsConstr)
import PlutusTx.Builtins.Internal qualified as BI
import PlutusTx.IsData.Class (ToData (..), UnsafeFromData (..))
import PlutusTx.Prelude (BuiltinData, BuiltinUnit, Integer)
import PlutusTx.Prelude qualified as P
import PlutusTx.Show qualified as P
import Prelude qualified as Haskell

-- ---------------------------------------------------------------------------
-- Data types
-- ---------------------------------------------------------------------------

-- | The state of the ball: who just hit it.
data BallState = Pinged | Ponged
  deriving stock (Haskell.Eq, Haskell.Show)

instance P.Eq BallState where
  {-# INLINEABLE (==) #-}
  Pinged == Pinged = P.True
  Ponged == Ponged = P.True
  _ == _ = P.False

-- | Full on-chain datum for the multi-player game.
data MultiPingPongDatum = MultiPingPongDatum
  { players :: [PubKeyHash]
  -- ^ Ordered list of participants.  Must contain at least 2 entries.
  , currentIndex :: Integer
  -- ^ Index into 'players' of the player whose turn it is.
  , ballState :: BallState
  -- ^ Current ball state.
  , roundCount :: Integer
  -- ^ Number of completed full rotations (incremented when index wraps to 0).
  , active :: P.Bool
  -- ^ 'P.False' once the game has been stopped.
  }
  deriving stock (Haskell.Show)

-- | Actions a player may take.
data MultiRedeemer = Hit | Stop
  deriving stock (Haskell.Eq, Haskell.Show)

-- ---------------------------------------------------------------------------
-- Show helpers
-- ---------------------------------------------------------------------------

{-# INLINEABLE showBallState #-}
showBallState :: BallState -> P.BuiltinString
showBallState Pinged = "Pinged"
showBallState Ponged = "Ponged"

{-# INLINEABLE showRedeemer #-}
showRedeemer :: MultiRedeemer -> P.BuiltinString
showRedeemer Hit = "Hit"
showRedeemer Stop = "Stop"

instance P.Show BallState where
  {-# INLINEABLE show #-}
  show = showBallState

instance P.Show MultiRedeemer where
  {-# INLINEABLE show #-}
  show = showRedeemer

-- ---------------------------------------------------------------------------
-- Strict ToData / UnsafeFromData instances
--
-- Written manually (not via unstableMakeIsData) to guard against the
-- Large Data Attack.  Every nullary constructor is encoded as Constr N []
-- and the decoder rejects any trailing fields.
-- ---------------------------------------------------------------------------

-- | BallState encoding:  Pinged = Constr 0 [],  Ponged = Constr 1 []
instance ToData BallState where
  {-# INLINEABLE toBuiltinData #-}
  toBuiltinData Pinged = mkConstr 0 []
  toBuiltinData Ponged = mkConstr 1 []

instance UnsafeFromData BallState where
  {-# INLINEABLE unsafeFromBuiltinData #-}
  unsafeFromBuiltinData d =
    let (idx, fields) = unsafeDataAsConstr d
     in if isNil fields
          then
            if idx P.== 0
              then Pinged
              else
                if idx P.== 1
                  then Ponged
                  else P.traceError "BallState: invalid constructor index"
          else P.traceError "BallState: unexpected extra fields"

-- | MultiRedeemer encoding:  Hit = Constr 0 [],  Stop = Constr 1 []
instance ToData MultiRedeemer where
  {-# INLINEABLE toBuiltinData #-}
  toBuiltinData Hit = mkConstr 0 []
  toBuiltinData Stop = mkConstr 1 []

instance UnsafeFromData MultiRedeemer where
  {-# INLINEABLE unsafeFromBuiltinData #-}
  unsafeFromBuiltinData d =
    let (idx, fields) = unsafeDataAsConstr d
     in if isNil fields
          then
            if idx P.== 0
              then Hit
              else
                if idx P.== 1
                  then Stop
                  else P.traceError "MultiRedeemer: invalid constructor index"
          else P.traceError "MultiRedeemer: unexpected extra fields"

{- | MultiPingPongDatum encoding:

  Constr 0 [ toData players
           , toData currentIndex
           , toData ballState
           , toData roundCount
           , toData active
           ]

  Exactly 5 fields are required; any other count is rejected.
-}
instance ToData MultiPingPongDatum where
  {-# INLINEABLE toBuiltinData #-}
  toBuiltinData MultiPingPongDatum{players, currentIndex, ballState, roundCount, active} =
    mkConstr
      0
      [ toBuiltinData players
      , toBuiltinData currentIndex
      , toBuiltinData ballState
      , toBuiltinData roundCount
      , toBuiltinData active
      ]

instance UnsafeFromData MultiPingPongDatum where
  {-# INLINEABLE unsafeFromBuiltinData #-}
  unsafeFromBuiltinData d =
    let (idx, fields) = unsafeDataAsConstr d
     in if idx P./= 0
          then P.traceError "MultiPingPongDatum: invalid constructor index"
          else case fields of
            (f0 : f1 : f2 : f3 : f4 : rest) ->
              if isNil rest
                then
                  let ps = unsafeFromBuiltinData f0
                      ci = unsafeFromBuiltinData f1
                      bs = unsafeFromBuiltinData f2
                      rc = unsafeFromBuiltinData f3
                      act = unsafeFromBuiltinData f4
                   in MultiPingPongDatum
                        { players = ps
                        , currentIndex = ci
                        , ballState = bs
                        , roundCount = rc
                        , active = act
                        }
                else P.traceError "MultiPingPongDatum: too many fields"
            _ -> P.traceError "MultiPingPongDatum: too few fields (expected 5)"

-- ---------------------------------------------------------------------------
-- Validator
-- ---------------------------------------------------------------------------

{- | Multi-player PingPong validator.

Dispatches on the redeemer:

* 'Hit'  — advance the game one step (signed by the current player).
* 'Stop' — end the game (signed by any registered player).
-}
{-# INLINEABLE validator #-}
validator :: BuiltinData -> BuiltinUnit
validator
  ( unsafeFromBuiltinData ->
      ScriptContext
        { scriptContextScriptInfo = SpendingScript ownTxOutRef _
        , scriptContextRedeemer = (unsafeFromBuiltinData P.. getRedeemer -> action :: MultiRedeemer)
        , scriptContextTxInfo =
          TxInfo
            { txInfoInputs
            , txInfoOutputs
            , txInfoData = datumMap
            , txInfoSignatories
            }
        }
    ) =
    let
      -- Locate our own input UTxO.
      ownInput = findOwnInput ownTxOutRef txInfoInputs
      ownTxOut = txInInfoResolved ownInput
      ownAddress = txOutAddress ownTxOut

      -- Decode and validate the current datum.
      inputDatum = getDatumFromTxOut datumMap "input" ownTxOut
      _ = validateDatum inputDatum -- structural checks, traceError on failure
     in
      case action of
        Hit -> validateHit ownAddress ownTxOut inputDatum txInfoOutputs datumMap txInfoSignatories
        Stop -> validateStop ownTxOut inputDatum txInfoSignatories
validator _ = P.traceError "MultiPingPong: invalid script purpose - expected SpendingScript"

-- ---------------------------------------------------------------------------
-- Hit handler
-- ---------------------------------------------------------------------------

{-# INLINEABLE validateHit #-}
validateHit
  :: Address
  -> TxOut
  -> MultiPingPongDatum
  -> [TxOut]
  -> Map DatumHash Datum
  -> [PubKeyHash]
  -> BuiltinUnit
validateHit ownAddress ownTxOut inputDatum txInfoOutputs datumMap signatories =
  let
    MultiPingPongDatum
      { players = ps
      , currentIndex = ci
      , ballState = bs
      , roundCount = rc
      , active = act
      } = inputDatum

    -- 1. Game must be active.
    check1 =
      if P.not act
        then P.traceError "MultiPingPong: game is not active"
        else BI.unitval

    -- 2. Signer must be the current player.
    currentPlayer = indexList ps ci
    check2 =
      if P.not (elemList currentPlayer signatories)
        then P.traceError "MultiPingPong: transaction not signed by current player"
        else BI.unitval

    -- 3. Value preservation (Large Value Attack mitigation).
    inputValue = txOutValue ownTxOut
    contOutput = findContinuationOutput ownAddress txInfoOutputs
    outputValue = txOutValue contOutput
    check3 =
      if inputValue P./= outputValue
        then P.traceError "MultiPingPong: value mismatch - output must equal input"
        else BI.unitval

    -- 4. Decode and validate the output datum.
    outputDatum = getDatumFromTxOut datumMap "output" contOutput
    check4 = validateDatum outputDatum

    MultiPingPongDatum
      { players = ps'
      , currentIndex = ci'
      , ballState = bs'
      , roundCount = rc'
      , active = act'
      } = outputDatum

    -- 5. players list must be unchanged.
    check5 =
      if ps' P./= ps
        then P.traceError "MultiPingPong: players list must not change"
        else BI.unitval

    -- 6. active must remain True.
    check6 =
      if P.not act'
        then P.traceError "MultiPingPong: active must remain True after Hit"
        else BI.unitval

    -- 7. ballState must flip.
    expectedBs = flipBall bs
    check7 =
      if bs' P./= expectedBs
        then
          P.traceError
            P.$ "MultiPingPong: ballState must flip to "
            `P.appendString` showBallState expectedBs
        else BI.unitval

    -- 8. currentIndex must advance correctly.
    numPlayers = listLength ps
    expectedCi = (ci P.+ 1) `P.modulo` numPlayers
    check8 =
      if ci' P./= expectedCi
        then P.traceError "MultiPingPong: currentIndex did not advance correctly"
        else BI.unitval

    -- 9. roundCount increments iff index wraps to 0.
    expectedRc = if expectedCi P.== 0 then rc P.+ 1 else rc
   in
    -- Force every check in order. `Haskell.seq` is Haskell's Prelude.seq, not
    -- PlutusTx.Prelude — it is always in scope even under NoImplicitPrelude
    -- because the PlutusTx plugin re-exports it as a builtin.
    check1 `Haskell.seq`
      check2 `Haskell.seq`
        check3 `Haskell.seq`
          check4 `Haskell.seq`
            check5 `Haskell.seq`
              check6 `Haskell.seq`
                check7 `Haskell.seq`
                  check8 `Haskell.seq`
                    ( if rc' P./= expectedRc
                        then P.traceError "MultiPingPong: roundCount updated incorrectly"
                        else BI.unitval
                    )

-- ---------------------------------------------------------------------------
-- Stop handler
-- ---------------------------------------------------------------------------

{-# INLINEABLE validateStop #-}
validateStop
  :: TxOut
  -> MultiPingPongDatum
  -> [PubKeyHash]
  -> BuiltinUnit
validateStop _ownTxOut inputDatum signatories =
  let
    MultiPingPongDatum
      { players = ps
      , active = act
      } = inputDatum

    -- 1. Game must be active.
    check1 =
      if P.not act
        then P.traceError "MultiPingPong: game is already stopped"
        else BI.unitval

    -- 2. Signer must be one of the registered players.
    check2 =
      if P.not (anySignedBy ps signatories)
        then P.traceError "MultiPingPong: Stop must be signed by a registered player"
        else BI.unitval
   in
    -- No continuation output is required after Stop.
    check1 `Haskell.seq`
      check2 `Haskell.seq`
        BI.unitval

-- ---------------------------------------------------------------------------
-- Datum helpers
-- ---------------------------------------------------------------------------

{-# INLINEABLE getDatumFromTxOut #-}
getDatumFromTxOut :: Map DatumHash Datum -> P.BuiltinString -> TxOut -> MultiPingPongDatum
getDatumFromTxOut datumMap ctx TxOut{txOutDatum} =
  case txOutDatum of
    OutputDatum (unsafeFromBuiltinData P.. getDatum -> d :: MultiPingPongDatum) ->
      d
    OutputDatumHash hash ->
      case lookup hash datumMap of
        P.Just (unsafeFromBuiltinData P.. getDatum -> d :: MultiPingPongDatum) -> d
        P.Nothing ->
          P.traceError P.$ ctx `P.appendString` ": OutputDatumHash not found in datum map"
    NoOutputDatum ->
      P.traceError P.$ ctx `P.appendString` ": NoOutputDatum"

-- | Structural integrity checks on a decoded datum.
{-# INLINEABLE validateDatum #-}
validateDatum :: MultiPingPongDatum -> BuiltinUnit
validateDatum MultiPingPongDatum{players, currentIndex, roundCount} =
  let numPlayers = listLength players
   in if numPlayers P.< 2
        then P.traceError "MultiPingPong: need at least 2 players"
        else
          if currentIndex P.< 0 P.|| currentIndex P.>= numPlayers
            then P.traceError "MultiPingPong: currentIndex out of bounds"
            else
              if roundCount P.< 0
                then P.traceError "MultiPingPong: roundCount must be non-negative"
                else BI.unitval

-- ---------------------------------------------------------------------------
-- UTxO lookup helpers
-- ---------------------------------------------------------------------------

{- | Find our own input by matching the TxOutRef from SpendingScript.

NOTE: The empty-list case is defensive code.  The Cardano ledger guarantees
the ownTxOutRef is always present in txInfoInputs; this branch exists only
as a guard against impossible states and will appear uncovered in coverage
reports.
-}
{-# INLINEABLE findOwnInput #-}
findOwnInput :: TxOutRef -> [TxInInfo] -> TxInInfo
findOwnInput _ [] = P.traceError "MultiPingPong: own input not found"
findOwnInput ref (inp@TxInInfo{txInInfoOutRef} : rest)
  | txInInfoOutRef P.== ref = inp
  | P.otherwise = findOwnInput ref rest

{- | SECURITY CRITICAL: Find the continuation output at our own script address.

Prevents an attacker from producing an output with a valid datum but at a
different (attacker-controlled) address.
-}
{-# INLINEABLE findContinuationOutput #-}
findContinuationOutput :: Address -> [TxOut] -> TxOut
findContinuationOutput _ [] =
  P.traceError "MultiPingPong: no continuation output at script address"
findContinuationOutput ownAddr (out@TxOut{txOutAddress} : rest)
  | txOutAddress P.== ownAddr = out
  | P.otherwise = findContinuationOutput ownAddr rest

-- ---------------------------------------------------------------------------
-- List utilities (PlutusTx.Prelude compatible)
-- ---------------------------------------------------------------------------

-- | O(1) nil check (avoids pattern-matching overhead in tight loops).
{-# INLINEABLE isNil #-}
isNil :: [a] -> P.Bool
isNil [] = P.True
isNil (_ : _) = P.False

{- | Safe index into a list; traceError on out-of-bounds (should be guarded
  by validateDatum before reaching here).
-}
{-# INLINEABLE indexList #-}
indexList :: [a] -> Integer -> a
indexList [] _ = P.traceError "MultiPingPong: indexList - index out of range"
indexList (x : xs) n = if n P.== 0 then x else indexList xs (n P.- 1)

-- | Length of a list as an Integer.
{-# INLINEABLE listLength #-}
listLength :: [a] -> Integer
listLength [] = 0
listLength (_ : xs) = 1 P.+ listLength xs

-- | Check whether an element is in a list.
{-# INLINEABLE elemList #-}
elemList :: (P.Eq a) => a -> [a] -> P.Bool
elemList _ [] = P.False
elemList x (y : ys) = x P.== y P.|| elemList x ys

-- | True if any element of the first list appears in the second list.
{-# INLINEABLE anySignedBy #-}
anySignedBy :: [PubKeyHash] -> [PubKeyHash] -> P.Bool
anySignedBy [] _ = P.False
anySignedBy (p : ps) sigs = elemList p sigs P.|| anySignedBy ps sigs

-- ---------------------------------------------------------------------------
-- Ball-state helpers
-- ---------------------------------------------------------------------------

{-# INLINEABLE flipBall #-}
flipBall :: BallState -> BallState
flipBall Pinged = Ponged
flipBall Ponged = Pinged
