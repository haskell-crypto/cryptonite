{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif
#if MIN_VERSION_integer_gmp(0,5,1)
{-# LANGUAGE UnboxedTuples #-}
#endif
#ifdef VERSION_integer_gmp
{-# LANGUAGE MagicHash #-}
#endif
-- |
-- Module      : Crypto.Number.Basic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.Basic
    ( sqrti
    , gcde
    , areEven
    , log2
    ) where

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
#else
import Data.Bits
#endif
#ifdef VERSION_integer_gmp
import GHC.Exts
import GHC.Integer.Logarithms (integerLog2#)
#endif

-- | sqrti returns two integer (l,b) so that l <= sqrt i <= b
-- the implementation is quite naive, use an approximation for the first number
-- and use a dichotomy algorithm to compute the bound relatively efficiently.
sqrti :: Integer -> (Integer, Integer)
sqrti i
    | i < 0     = error "cannot compute negative square root"
    | i == 0    = (0,0)
    | i == 1    = (1,1)
    | i == 2    = (1,2)
    | otherwise = loop x0
        where
            nbdigits = length $ show i
            x0n = (if even nbdigits then nbdigits - 2 else nbdigits - 1) `div` 2
            x0  = if even nbdigits then 2 * 10 ^ x0n else 6 * 10 ^ x0n
            loop x = case compare (sq x) i of
                LT -> iterUp x
                EQ -> (x, x)
                GT -> iterDown x
            iterUp lb = if sq ub >= i then iter lb ub else iterUp ub
                where ub = lb * 2
            iterDown ub = if sq lb >= i then iterDown lb else iter lb ub
                where lb = ub `div` 2
            iter lb ub
                | lb == ub   = (lb, ub)
                | lb+1 == ub = (lb, ub)
                | otherwise  =
                    let d = (ub - lb) `div` 2 in
                    if sq (lb + d) >= i
                        then iter lb (ub-d)
                        else iter (lb+d) ub
            sq a = a * a

-- | get the extended GCD of two integer using integer divMod
--
-- gcde 'a' 'b' find (x,y,gcd(a,b)) where ax + by = d
--
gcde :: Integer -> Integer -> (Integer, Integer, Integer)
#if MIN_VERSION_integer_gmp(0,5,1)
gcde a b = (s, t, g)
  where (# g, s #) = gcdExtInteger a b
        t = (g - s * a) `div` b
#else
gcde a b = if d < 0 then (-x,-y,-d) else (x,y,d) where
    (d, x, y)                     = f (a,1,0) (b,0,1)
    f t              (0, _, _)    = t
    f (a', sa, ta) t@(b', sb, tb) =
        let (q, r) = a' `divMod` b' in
        f t (r, sa - (q * sb), ta - (q * tb))
#endif


-- | check if a list of integer are all even
areEven :: [Integer] -> Bool
areEven = and . map even

log2 :: Integer -> Int
#ifdef VERSION_integer_gmp
log2 0 = 0
log2 x = I# (integerLog2# x)
#else
-- http://www.haskell.org/pipermail/haskell-cafe/2008-February/039465.html
log2 = imLog 2
  where
    imLog b x = if x < b then 0 else (x `div` b^l) `doDiv` l
      where
        l = 2 * imLog (b * b) x
        doDiv x' l' = if x' < b then l' else (x' `div` b) `doDiv` (l' + 1)
#endif
{-# INLINE log2 #-}
