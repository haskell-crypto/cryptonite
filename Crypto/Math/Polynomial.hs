{-# LANGUAGE BangPatterns #-}
-- |
-- Module      : Crypto.Math.Polynomial
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Math.Polynomial
    ( Monomial(..)
    -- * Polynomial operations
    , Polynomial
    , toList
    , fromList
    , addPoly
    , subPoly
    , mulPoly
    , squarePoly
    , expPoly
    , divPoly
    , negPoly
    ) where

import Data.List (intercalate, sort)
import Data.Vector ((!), Vector)
import qualified Data.Vector as V
import Control.Arrow (first)

data Monomial = Monomial {-# UNPACK #-} !Int !Integer
    deriving (Eq)

data Polynomial = Polynomial (Vector Monomial)
    deriving (Eq)

instance Ord Monomial where
    compare (Monomial w1 v1) (Monomial w2 v2) =
        case compare w1 w2 of
            EQ -> compare v1 v2
            r  -> r

instance Show Monomial where
    show (Monomial w v) = show v ++ "x^" ++ show w

instance Show Polynomial where
    show (Polynomial p) = intercalate "+" $ map show $ V.toList p

toList :: Polynomial -> [Monomial]
toList (Polynomial p) = V.toList p

fromList :: [Monomial] -> Polynomial
fromList = Polynomial . V.fromList . reverse . sort . filterZero
    where
        filterZero = filter (\(Monomial _ v) -> v /= 0)

getWeight :: Polynomial -> Int -> Maybe Integer
getWeight (Polynomial p) n = look 0
    where
        plen = V.length p
        look !i
            | i >= plen = Nothing
            | otherwise =
                let (Monomial w v) = p ! i in
                case compare w n of
                    LT -> Nothing
                    EQ -> Just v
                    GT -> look (i+1)
        

mergePoly :: (Integer -> Integer -> Integer) -> Polynomial -> Polynomial -> Polynomial
mergePoly f (Polynomial p1) (Polynomial p2) = fromList $ loop 0 0
    where
        l1 = V.length p1
        l2 = V.length p2
        loop !i1 !i2
            | i1 == l1 && i2 == l2 = []
            | i1 == l1             = (p2 ! i2) : loop i1 (i2+1)
            | i2 == l2             = (p1 ! i1) : loop (i1+1) i2
            | otherwise            =
                let (coef, i1inc, i2inc) = addCoef (p1 ! i1) (p2 ! i2) in
                coef : loop (i1+i1inc) (i2+i2inc)
        addCoef m1@(Monomial w1 v1) (Monomial w2 v2) =
            case compare w1 w2 of
                LT -> (Monomial w2 (f 0 v2), 0, 1)
                EQ -> (Monomial w1 (f v1 v2), 1, 1)
                GT -> (m1, 1, 0)

addPoly :: Polynomial -> Polynomial -> Polynomial
addPoly = mergePoly (+)

subPoly :: Polynomial -> Polynomial -> Polynomial
subPoly = mergePoly (-)

negPoly :: Polynomial -> Polynomial
negPoly (Polynomial p) = Polynomial $ V.map negateMonomial p
    where negateMonomial (Monomial w v) = Monomial w (-v)

mulPoly :: Polynomial -> Polynomial -> Polynomial
mulPoly p1@(Polynomial v1) p2@(Polynomial v2) =
    fromList $ filter (\(Monomial _ v) -> v /= 0) $ map (\i -> Monomial i (c i)) $ reverse [0..(m+n)]
    where
        (Monomial m _) = v1 ! 0
        (Monomial n _) = v2 ! 0
        c r = foldl (\acc i -> (b $ r-i) * (a $ i) + acc) 0 [0..r]
            where
                a = maybe 0 id . getWeight p1
                b = maybe 0 id . getWeight p2

squarePoly :: Polynomial -> Polynomial
squarePoly p = p `mulPoly` p

expPoly :: Polynomial -> Integer -> Polynomial
expPoly p e = loop p e
    where
        loop t 0 = t
        loop t n = loop (squarePoly t) (n-1)

divPoly :: Polynomial -> Polynomial -> (Polynomial, Polynomial)
divPoly p1 p2@(Polynomial pp2) = first fromList $ divLoop p1
    where divLoop d1@(Polynomial pp1)
            | V.null pp1 = ([], d1)
            | otherwise  =
                let (Monomial w1 v1) = pp1 ! 0 in
                let (Monomial w2 v2) = pp2 ! 0 in
                let w = w1 - w2 in
                let (v,r) = v1 `divMod` v2 in
                if w >= 0 && r == 0
                    then
                        let mono = (Monomial w v) in
                        let remain = d1 `subPoly` (p2 `mulPoly` (fromList [mono])) in
                        let (l, finalRem) = divLoop remain in
                        (mono : l, finalRem)
                    else
                        ([], d1)
