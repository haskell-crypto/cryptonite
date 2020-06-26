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
    (
    -- * Types
      Template
    , Attrs
    -- * methods
    , parseTemplate
    , renderTemplate
    ) where

import Data.Char (isDigit, isAlpha)
import Data.List (isPrefixOf)
import Control.Applicative
import Control.Monad

data TAtom =
      Text String
    | Var String
    | Tpl String Template
    deriving (Show)

type Template = [TAtom]

type Attrs = [(String, String)]

renderTemplate :: Template
               -> Attrs
               -> [(String, [Attrs])]
               -> String
renderTemplate template attrs multiAttrs =
    concat $ map renderAtom template
  where
        renderAtom :: TAtom -> String
        renderAtom (Text b)  = b
        renderAtom (Var s)   = maybe "" id $ lookup s attrs
        renderAtom (Tpl n t) =
            case lookup n multiAttrs of
                Nothing     -> error ("cannot find inner template attributes for: " ++ n)
                Just []     -> ""
                Just (i:is) ->
                    renderTemplate t (i ++ attrs) [] ++
                    concatMap (\inAttrs -> renderTemplate t (inAttrs ++ attrs ++ [("COMMA", ",")]) []) is

parseTemplate :: String -> Template
parseTemplate = parseTemplateFromTokens . tokenize

parseTemplateFromTokens :: [Token] -> Template
parseTemplateFromTokens toks =
    case runStreamParser parse toks of
        Left err           -> error ("template parse error: " ++ err)
        Right (tatoms, []) -> tatoms
        Right (_, over)    -> error ("template left over: " ++ show over)
  where parse = do
            done <- isDone
            if done
                then return []
                else do next <- getTemplate <|> getVariable <|> getOther
                        liftM (next:) parse

------------------------------------------------------------------------
-- parser methods
------------------------------------------------------------------------
getVariable :: StreamParser TAtom
getVariable = StreamParser $ \toks ->
    case toks of
        [] -> Left "variable: end of stream"
        TokVariableMarker:TokText t:TokVariableMarker:rest
            | isVariable t -> Right (Var t, rest)
            | otherwise    -> Left "not a variable, variable name invalid"
        _ -> Left "not a variable: not starting by %%"

getTemplate :: StreamParser TAtom
getTemplate = StreamParser $ \toks ->
    case toks of
        [] -> Left "template: end of stream"
        TokGroupStart:TokText t:TokGroupEnd:rest
            | isVariable t ->
                case break (== TokGroupStart) rest of
                    (_, []) -> Left "template: no end found"
                    (inner, TokGroupStart:TokText t2:TokGroupEnd:rest2)
                        | isVariable t2 ->
                            if t == t2
                                then Right (Tpl t (parseTemplateFromTokens inner), rest2)
                                else Left ("template: end name " ++ show t2 ++ " not matching start name " ++ show t)
                        | otherwise -> Left "template: end sequence: invalid name"
                    (_, _) -> Left "template: end sequence: not found"
            | otherwise -> Left "template: start sequence: invalid name"
        _ -> Left "template: not right starting sequence"

getOther :: StreamParser TAtom
getOther = StreamParser $ \toks ->
    case toks of
        (x:xs) -> Right (Text (show x), xs)
        []     -> Left "getOther: end of string"

isVariable :: String -> Bool
isVariable = and . map isVariableChar
    where isVariableChar :: Char -> Bool
          isVariableChar c = isAlpha c || isDigit c || c == '_'

isDone :: StreamParser Bool
isDone = StreamParser $ \s -> Right (null s, s)

------------------------------------------------------------------------
-- parser subsystem
------------------------------------------------------------------------
newtype StreamParser a = StreamParser { runStreamParser :: [Token] -> Either String (a, [Token]) }

instance Functor StreamParser where
    fmap f x = StreamParser $ \s ->
        case (runStreamParser x) s of
            Right (a, s') -> Right (f a, s')
            Left err      -> Left err
instance Applicative StreamParser where
    pure       = return
    (<*>) fm m = StreamParser $ \s1 ->
        case runStreamParser m s1 of
            Left err      -> Left err
            Right (a, s2) ->
                case runStreamParser fm s2 of
                    Left err      -> Left err
                    Right (f, s3) -> Right (f a, s3)
instance Alternative StreamParser where
    empty = mzero
    (<|>) = mplus
instance Monad StreamParser where
    return a    = StreamParser $ \s -> Right (a, s)
    (>>=) m1 m2 = StreamParser $ \s1 ->
        case (runStreamParser m1) s1 of
            Left err      -> Left err
            Right (a, s2) -> runStreamParser (m2 a) s2
instance MonadPlus StreamParser where
    mzero       = StreamParser $ \_ -> Left "empty"
    mplus m1 m2 = StreamParser $ \s ->
        case (runStreamParser m1) s of
            Left _        -> (runStreamParser m2) s
            Right (a, s2) -> Right (a, s2)

------------------------------------------------------------------------
-- token parsing
------------------------------------------------------------------------

data Token = TokVariableMarker
           | TokGroupStart
           | TokGroupEnd
           | TokText String
           deriving (Eq)

instance Show Token where
    show TokVariableMarker = "%%"
    show TokGroupStart     = "%{"
    show TokGroupEnd       = "%}"
    show (TokText t)       = t

tokenize :: String -> [Token]
tokenize s
    | "%%" `isPrefixOf` s = TokVariableMarker : tokenize (drop 2 s)
    | "%{" `isPrefixOf` s = TokGroupStart : tokenize (drop 2 s)
    | "%}" `isPrefixOf` s = TokGroupEnd : tokenize (drop 2 s)
    | otherwise           =
        case break (== '%') s of
            (t, "")  -> [TokText t]
            (t1, t2) -> TokText t1 : tokenize t2
