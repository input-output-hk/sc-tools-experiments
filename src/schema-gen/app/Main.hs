module Main where

import Data.Aeson.Encode.Pretty (encodePretty)
import Data.ByteString.Lazy.Char8 qualified as BL

import Convex.SchemaGen (streamingEventSchema)

main :: IO ()
main = BL.putStrLn $ encodePretty streamingEventSchema
