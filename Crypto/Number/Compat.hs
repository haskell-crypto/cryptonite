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
    , onGmpUnsupported
    , gmpGcde
    , gmpLog2
    , gmpPowModSecInteger
    , gmpPowModInteger
    , gmpInverse
    , gmpNextPrime
    , gmpTestPrimeMillerRabin
    , gmpSizeInBytes
    , gmpExportInteger
    , gmpImportInteger
    ) where

#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
import GHC.Base
import GHC.Integer.Logarithms (integerLog2#)
#endif
import Data.Word
import GHC.Ptr (Ptr(..))

data GmpSupported a = GmpSupported a
                    | GmpUnsupported
                    deriving (Show,Eq)

onGmpUnsupported :: GmpSupported a -> a -> a
onGmpUnsupported (GmpSupported a) _ = a
onGmpUnsupported GmpUnsupported   f = f

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

gmpSizeInBytes :: Integer -> GmpSupported Int
#if MIN_VERSION_integer_gmp(0,5,1)
gmpSizeInBytes n = GmpSupported (I# (word2Int# (sizeInBaseInteger n 256#)))
#else
gmpSizeInBytes _ = GmpUnsupported
#endif

gmpExportInteger :: Integer -> Ptr Word8 -> GmpSupported (IO ())
#if __GLASGOW_HASKELL__ >= 710
gmpExportInteger n (Ptr addr) = GmpSupported $ do
    _ <- exportIntegerToAddr n addr 1#
    return ()
#elif MIN_VERSION_integer_gmp(0,5,1)
gmpExportInteger n (Ptr addr) = GmpSupported $ IO $ \s ->
    case exportIntegerToAddr n addr 1# s of
        (# s2, _ #) -> (# s2, () #)
#else
gmpExportInteger _ _ = GmpUnsupported
#endif

gmpImportInteger :: Int -> Ptr Word8 -> GmpSupported (IO Integer)
#if __GLASGOW_HASKELL__ >= 710
gmpImportInteger n (Ptr addr) = GmpSupported $
    importIntegerFromAddr addr (int2Word# n) 1#
#elif MIN_VERSION_integer_gmp(0,5,1)
gmpImportInteger n (Ptr addr) = GmpSupported $ IO $ \s ->
    importIntegerFromAddr addr (int2Word# n) 1# s
#else
gmpImportInteger _ _ = GmpUnsupported
#endif
