{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

module Convex.ThreatModel.Pretty where

import Cardano.Api hiding (Doc, (<+>))

-- import Cardano.Api.Byron hiding (Doc, (<+>))
import Cardano.Ledger.Alonzo.Tx qualified as Ledger (Data)
import Cardano.Ledger.Alonzo.TxWits qualified as Ledger

import Cardano.Ledger.Alonzo.Scripts qualified as Ledger
import Cardano.Ledger.Conway.Scripts qualified as Conway
import Cardano.Ledger.Hashes qualified as Ledger
import Data.ByteString qualified as BS
import Data.Char
import Data.List (nub, sort)
import Data.Map qualified as Map
import GHC.Exts (toList)

import Text.PrettyPrint.HughesPJClass hiding ((<>))
import Text.Printf

import Convex.ThreatModel.Cardano.Api
import Convex.ThreatModel.TxModifier

{- | Format a list of strings as a paragraph. The structure of the list is not considered other than
  inserting whitespace between consecutive elements. Use with
  `Test.QuickCheck.ContractModel.ThreatModel.counterexampleTM`
  when printing longer texts.
-}
paragraph :: [String] -> String
paragraph s = show $ (fsep . map text . words . unwords $ s) $$ text ""

block :: Doc -> [Doc] -> Doc
block hd body = hd $$ nest 2 (vcat body)

fblock :: Doc -> [Doc] -> Doc
fblock hd body = hang hd 2 $ fsep body

hblock :: Doc -> [Doc] -> Doc
hblock hd body = hd <+> fsep body

pList :: [Doc] -> Doc
pList = brackets . fsep . punctuate comma

pSet :: [Doc] -> Doc
pSet = braces . fsep . punctuate comma

pArgs :: [Doc] -> Doc
pArgs = parens . fsep . punctuate comma

infixr 6 <:>
(<:>) :: Doc -> Doc -> Doc
a <:> b = (a <> text ":") <+> b

prettyInput :: Input -> Doc
prettyInput (Input txout txin) =
  prettyIn txin <:> prettyTxOut txout

prettyOutput :: Output -> Doc
prettyOutput (Output txout (TxIx i)) =
  brackets (text $ show i) <:> prettyTxOutTx txout

prettyUTxO :: UTxO Era -> Doc
prettyUTxO (UTxO utxos) =
  block
    (text "UTxOs")
    [ (prettyIn i <> text ":") $$ nest ind (prettyTxOut o)
    | (i, o) <- Map.toList utxos
    ]
 where
  ind
    | or [i > 9 | TxIn _ (TxIx i) <- Map.keys utxos] = 13
    | otherwise = 12

prettyIn :: TxIn -> Doc
prettyIn (TxIn hash ix) =
  prettyHash hash <> brackets (prettyIx ix)

prettyTxOut :: TxOut CtxUTxO Era -> Doc
prettyTxOut (TxOut (AddressInEra _ addr) value datum rscript) =
  hblock
    (text "TxOut")
    [ prettyAddress (toAddressAny addr)
    , prettyValue (txOutValueToValue value)
    , prettyDatum datum'
    , prettyRefScript rscript
    ]
 where
  datum' = case datum of
    TxOutDatumNone -> TxOutDatumNone
    TxOutDatumHash s h -> TxOutDatumHash s h
    TxOutDatumInline s sd -> TxOutDatumInline s sd

prettyTxOutTx :: TxOut CtxTx Era -> Doc
prettyTxOutTx (TxOut (AddressInEra _ addr) value datum rscript) =
  hblock
    (text "TxOut")
    [ prettyAddress (toAddressAny addr)
    , prettyValue (txOutValueToValue value)
    , prettyDatum datum
    , prettyRefScript rscript
    ]

prettyAddress :: AddressAny -> Doc
prettyAddress (AddressByron (ByronAddress a)) = text $ show a
prettyAddress (AddressShelley (ShelleyAddress _ c _)) =
  case fromShelleyPaymentCredential c of
    PaymentCredentialByKey h -> text "Key#" <> prettyHash h
    PaymentCredentialByScript h -> text "Script#" <> prettyHash h

prettyIx :: TxIx -> Doc
prettyIx (TxIx txIx) = text $ show txIx

prettyValue :: Value -> Doc
prettyValue value =
  pSet
    [ prettyAssetId assetId <:> text (show num)
    | (assetId, num) <- toList value
    ]

prettyAssetId :: AssetId -> Doc
prettyAssetId AdaAssetId = text "lovelace"
prettyAssetId (AssetId hash name) = prettyHash hash <> text "." <> prettyName name
 where
  prettyName n = prettyBytes False (serialiseToRawBytes n)

prettyHash :: (Show a) => a -> Doc
prettyHash = text . take 7 . drop 1 . show

prettyDatum :: Datum -> Doc
prettyDatum TxOutDatumNone = text "Datum#None"
prettyDatum (TxOutDatumHash _ h) = text "Datum#" <> prettyHash h
prettyDatum (TxOutDatumInline _ d) = prettyScriptData $ getScriptData d
prettyDatum (TxOutSupplementalDatum _ d) = prettyScriptData $ getScriptData d

prettyRefScript :: ReferenceScript Era -> Doc
prettyRefScript ReferenceScriptNone = text "RefScript#None"
prettyRefScript (ReferenceScript _ s) = text "RefScript#" <> prettyScript s

prettyScript :: ScriptInAnyLang -> Doc
prettyScript (ScriptInAnyLang _ s) = prettyHash (hashScript s)

prettyTx :: Tx Era -> Doc
prettyTx tx@(Tx body _) =
  block (text "Tx") $
    [ text "Valid:" <+> prettyValidity (txValidityLowerBound, txValidityUpperBound)
    , fblock (text "Inputs:") $ map prettyIn inps
    ]
      ++ [ fblock (text "Reference inputs:") $ map prettyIn refinps
         | TxInsReference _ refinps _ <- [txInsReference]
         ]
      ++ [ block
             (text "Outputs:")
             [ int i <:> prettyTxOutTx out
             | (i, out) <- zip [0 ..] txOuts
             ]
         , prettyMinting txMintValue
         , prettyDatumMap scriptdat
         , block (text "Redeemers:") $ map (uncurry $ prettyRedeemer inps mnts) $ Map.toList rdmrs
         , block (text "Signed by:") $ map prettyHash (txSigners tx)
         ]
 where
  TxBodyContent{..} = getTxBodyContent body
  ShelleyTxBody _ _ _ scriptdat _ _ = body
  inps = sort . map fst $ txIns
  mnts = case txMintValue of
    TxMintNone -> []
    TxMintValue{} -> [hash | AssetId hash _ <- sort . nub . map fst $ toList (txMintValueToValue txMintValue)]
  rdmrs = case scriptdat of
    TxBodyScriptData _ _ (Ledger.Redeemers rdmrs') -> rdmrs'
    TxBodyNoScriptData -> mempty

prettyRedeemer :: [TxIn] -> [PolicyId] -> Ledger.PlutusPurpose Ledger.AsIx LedgerEra -> (Ledger.Data LedgerEra, Ledger.ExUnits) -> Doc
prettyRedeemer inps mints purpose (dat, _) = pTag <:> prettyScriptData (getScriptData $ fromAlonzoData dat)
 where
  pTag =
    case purpose of
      Conway.ConwaySpending (Ledger.AsIx ix) -> text "Spend" <+> prettyIn (inps !! fromIntegral ix)
      Conway.ConwayMinting (Ledger.AsIx ix) -> text "Mint" <+> prettyHash (mints !! fromIntegral ix)
      Conway.ConwayCertifying _ -> text "Certify"
      Conway.ConwayRewarding _ -> text "Reward"
      Conway.ConwayVoting _ -> text "Vote"
      Conway.ConwayProposing _ -> text "Propose"

prettyDatumMap :: TxBodyScriptData Era -> Doc
prettyDatumMap (TxBodyScriptData _ (Ledger.TxDats dats) _)
  | not $ null dats =
      block
        (text "Datums:")
        [ prettyHash (Ledger.extractHash key)
            <:> prettyScriptData (getScriptData $ fromAlonzoData val)
        | (key, val) <- Map.toList dats
        ]
prettyDatumMap _ = empty

prettyMinting :: TxMintValue build Era -> Doc
prettyMinting TxMintNone = empty
prettyMinting mv@TxMintValue{} = block (text "Minting:") [prettyValue (txMintValueToValue mv)]

prettyValidity :: (TxValidityLowerBound Era, TxValidityUpperBound Era) -> Doc
prettyValidity (lo, hi) = prettyLowerBound lo <+> text "-" <+> prettyUpperBound hi

prettyLowerBound :: TxValidityLowerBound Era -> Doc
prettyLowerBound TxValidityNoLowerBound = text "-∞"
prettyLowerBound (TxValidityLowerBound _ slot) = text (show $ unSlotNo slot)

prettyUpperBound :: TxValidityUpperBound Era -> Doc
prettyUpperBound (TxValidityUpperBound _ Nothing) = text "∞"
prettyUpperBound (TxValidityUpperBound _ (Just slot)) = text (show $ unSlotNo slot)

prettyPlutusV2Script :: PlutusScript PlutusScriptV2 -> Doc
prettyPlutusV2Script = prettyHash . hashScript . PlutusScript PlutusScriptV2

prettySimpleScript :: SimpleScript -> Doc
prettySimpleScript = prettyHash . hashScript . SimpleScript

prettyTxModifier :: TxModifier -> Doc
prettyTxModifier (TxModifier txmod) = vcat [prettyMod m | m <- txmod]
 where
  maybeBlock _ _ _ Nothing = empty
  maybeBlock tag hd pr (Just d) = hang tag 2 $ fsep [hd, pr d]

  prettyMod (RemoveInput txIn) =
    text "removeInput" <+> prettyIn txIn
  prettyMod (RemoveOutput ix) =
    text "removeOutput" <+> prettyIx ix
  prettyMod (ChangeOutput ix maddr mvalue mdatum mrefscript) =
    vcat
      [ maybeBlock (text "changeAddressOf") (prettyIx ix) prettyAddress maddr
      , maybeBlock (text "changeValueOf") (prettyIx ix) prettyValue mvalue
      , maybeBlock (text "changeDatumOf") (prettyIx ix) prettyDatum mdatum
      , maybeBlock (text "changeRefScriptOf") (prettyIx ix) prettyRefScript mrefscript
      ]
  prettyMod (ChangeInput txIn maddr mvalue mdatum mrefscript) =
    vcat
      [ maybeBlock (text "changeAddressOf") (prettyIn txIn) prettyAddress maddr
      , maybeBlock (text "changeValueOf") (prettyIn txIn) prettyValue mvalue
      , maybeBlock (text "changeDatumOf") (prettyIn txIn) prettyDatum mdatum
      , maybeBlock (text "changeRefScriptOf") (prettyIn txIn) prettyRefScript mrefscript
      ]
  prettyMod (ChangeScriptInput txIn mvalue mdatum mrdmr mrefscript) =
    vcat
      [ maybeBlock (text "changeValueOf") (prettyIn txIn) prettyValue mvalue
      , maybeBlock (text "changeDatumOf") (prettyIn txIn) prettyDatum mdatum
      , maybeBlock (text "changeRedeemerOf") (prettyIn txIn) prettyScriptData mrdmr
      , maybeBlock (text "changeRefScriptOf") (prettyIn txIn) prettyRefScript mrefscript
      ]
  prettyMod (AddOutput addr value datum refscript) =
    fblock
      (text "addOutput")
      [ prettyAddress addr
      , prettyValue value
      , prettyDatum datum
      , prettyRefScript refscript
      ]
  prettyMod (AddInput addr value datum rscript isReferenceInput) =
    fblock
      (text "add" <> input)
      [ prettyAddress addr
      , prettyValue value
      , prettyDatum datum
      , prettyRefScript rscript
      ]
   where
    input
      | isReferenceInput = text "ReferenceInput"
      | otherwise = text "Input"
  prettyMod (AddPlutusScriptInput script value datum redeemer rscript) =
    fblock
      (text "addPlutusScriptInput")
      [ prettyPlutusV2Script script
      , prettyValue value
      , prettyDatum datum
      , prettyScriptData redeemer
      , prettyRefScript rscript
      ]
  prettyMod (AddReferenceScriptInput script value datum redeemer) =
    fblock
      (text "addReferenceScriptInput")
      [ prettyHash script
      , prettyValue value
      , prettyDatum datum
      , prettyScriptData redeemer
      ]
  prettyMod (AddPlutusScriptReferenceInput script value datum rscript) =
    fblock
      (text "addPlutusScriptReferenceInput")
      [ prettyPlutusV2Script script
      , prettyValue value
      , prettyDatum datum
      , prettyRefScript rscript
      ]
  prettyMod (AddSimpleScriptInput script value rscript isReferenceInput) =
    fblock
      (text "addSimpleScript" <> input)
      [ prettySimpleScript script
      , prettyValue value
      , prettyRefScript rscript
      ]
   where
    input
      | isReferenceInput = text "ReferenceInput"
      | otherwise = text "Input"
  prettyMod (ChangeValidityRange (Just lo) (Just hi)) =
    fblock (text "changeValidityRange") [prettyValidity (lo, hi)]
  prettyMod (ChangeValidityRange mlo mhi) =
    vcat
      [ maybeBlock (text "changeValidityLowerBound") empty prettyLowerBound mlo
      , maybeBlock (text "changeValidityUpperBound") empty prettyUpperBound mhi
      ]
  prettyMod (AddPlutusScriptMint script assetName quantity redeemer) =
    fblock
      (text "addPlutusScriptMint")
      [ prettyPlutusV2Script script
      , text (show assetName)
      , text (show quantity)
      , prettyScriptData redeemer
      ]
  prettyMod (ReplaceTx tx utxos) =
    fblock
      (text "replaceTx")
      [ prettyUTxO utxos
      , prettyTx tx
      ]

prettyScriptData :: ScriptData -> Doc
prettyScriptData (ScriptDataConstructor i args) = text "Con" <> text (show i) <> pArgs (map prettyScriptData args)
prettyScriptData (ScriptDataMap map') =
  pSet
    [prettyScriptData k <:> prettyScriptData v | (k, v) <- map']
prettyScriptData (ScriptDataList list) = pList $ map prettyScriptData list
prettyScriptData (ScriptDataNumber n) = text (show n)
prettyScriptData (ScriptDataBytes bs) = prettyBytes True bs

prettyBytes :: Bool -> BS.ByteString -> Doc
prettyBytes quotes' bs
  | not (all isPrint s) = text $ take 7 $ concatMap (printf "%02x" . fromEnum) s
  | quotes' = text (show bs)
  | otherwise = text s
 where
  s = map (toEnum . fromIntegral) $ BS.unpack bs
