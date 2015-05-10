-- |
-- Module      : Crypto.Number.Compat
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE CPP           #-}
{-# LANGUAGE MagicHash     #-}
{-# LANGUAGE BangPatterns  #-}
{-# LANGUAGE UnboxedTuples #-}
module Crypto.Number.Compat
    ( GmpSupported(..)
    , gmpGcde
    , gmpLog2
    , gmpPowModSecInteger
    , gmpPowModInteger
    , gmpInverse
    , gmpNextPrime
    , gmpTestPrimeMillerRabin
    ) where

#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
import GHC.Base
import GHC.Integer.Logarithms (integerLog2#)
#endif

data GmpSupported a = GmpSupported a
                    | GmpUnsupported
                    deriving (Show,Eq)

gmpGcde :: Integer -> Integer -> GmpSupported (Integer, Integer, Integer)
#if MIN_VERSION_integer_gmp(0,5,1)
gmpGcde a b =
    GmpSupported (s, t, g)
  where (# g, s #) = gcdExtInteger a b
        t = (g - s * a) `div` b
#else
gmpGcde _ _ = GmpUnsupported
#endif

gmpLog2 :: Integer -> GmpSupported Int
#ifdef VERSION_integer_gmp
gmpLog2 0 = GmpSupported 0
gmpLog2 x = GmpSupported (I# (integerLog2# x))
#else
gmpLog2 _ = GmpUnsupported
#endif

gmpPowModSecInteger :: Integer -> Integer -> Integer -> GmpSupported Integer
#if MIN_VERSION_integer_gmp(1,0,0)
gmpPowModSecInteger b e m = GmpUnsupported
#elif MIN_VERSION_integer_gmp(0,5,1)
gmpPowModSecInteger b e m = GmpSupported (powModSecInteger b e m)
#else
gmpPowModSecInteger _ _ _ = GmpUnsupported
#endif

gmpPowModInteger :: Integer -> Integer -> Integer -> GmpSupported Integer
#if MIN_VERSION_integer_gmp(0,5,1)
gmpPowModInteger b e m = GmpSupported (powModInteger b e m)
#else
gmpPowModInteger _ _ _ = GmpUnsupported
#endif

gmpInverse :: Integer -> Integer -> GmpSupported (Maybe Integer)
#if MIN_VERSION_integer_gmp(0,5,1)
gmpInverse g m
    | r == 0    = GmpSupported Nothing
    | otherwise = GmpSupported (Just r)
  where r = recipModInteger g m
#else
gmpInverse _ _ = GmpUnsupported
#endif

gmpNextPrime :: Integer -> GmpSupported Integer
#if MIN_VERSION_integer_gmp(0,5,1)
gmpNextPrime n = GmpSupported (nextPrimeInteger n)
#else
gmpNextPrime _ = GmpUnsupported
#endif

gmpTestPrimeMillerRabin :: Int -> Integer -> GmpSupported Bool
#if MIN_VERSION_integer_gmp(0,5,1)
gmpTestPrimeMillerRabin (I# tries) !n = GmpSupported $
    case testPrimeInteger n tries of
        0# -> False
        _  -> True
#else
gmpTestPrimeMillerRabin _ _ = GmpUnsupported
#endif
