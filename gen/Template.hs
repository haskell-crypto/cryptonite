-- |
-- Module      : Template
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : portable
--
-- A very simple template engine
--
module Template
    ( Template
    , parseTemplate
    , renderTemplate
    ) where

import Data.Char (isDigit, isAlpha)
import Data.List (isPrefixOf)

data TAtom = Text String | Var String deriving (Show)
type Template = [TAtom]

renderTemplate :: Template -> [(String,String)] -> String
renderTemplate template attrs =
    concat $ map renderAtom template
  where
        renderAtom :: TAtom -> String
        renderAtom (Text b) = b
        renderAtom (Var s)  = maybe "" id $ lookup s attrs

parseTemplate :: String -> Template
parseTemplate content 
    | null content            = []
    | isPrefixOf "%%" content = parseVar $ tailMarker content
    | otherwise               = parseText content
  where
        parseText :: String -> Template
        parseText s
            | null s    = []
            | otherwise = Text b : (parseVar $ tailMarker a)
          where
                (b, a) = grabUntilMarker s

        parseVar :: String -> Template
        parseVar s
            | null s    = []
            | otherwise =
                let (b, a) = grabUntilMarker s in
                if isVariable b
                    then Var b  : (parseText $ tailMarker a)
                    else Text b : (parseVar $ tailMarker a)

        isVariable :: String -> Bool
        isVariable = and . map isVariableChar
          where isVariableChar :: Char -> Bool
                isVariableChar c = isAlpha c || isDigit c || c == '_'

        tailMarker ('%':'%':xs) = xs
        tailMarker s            = s
            
        grabUntilMarker = loop
          where loop []             = ([], [])
                loop l@('%':'%':xs) = ([], l)
                loop (x:xs)         =
                    let (l1,l2) = loop xs
                     in (x:l1,l2)
