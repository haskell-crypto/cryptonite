{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE CPP #-}
#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif
-- |
-- Module      : Crypto.Number.ModArithmetic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.ModArithmetic
    (
    -- * exponentiation
      expSafe
    , expFast
    , exponentiation_rtl_binary
    , exponentiation
    -- * deprecated name for exponentiation
    , exponantiation_rtl_binary
    , exponantiation
    -- * inverse computing
    , inverse
    , inverseCoprimes
    ) where

import Control.Exception (throw, Exception)
import Data.Typeable

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
#else
import Crypto.Number.Basic (gcde)
import Data.Bits
#endif

-- | Raised when two numbers are supposed to be coprimes but are not.
data CoprimesAssertionError = CoprimesAssertionError
    deriving (Show,Typeable)

instance Exception CoprimesAssertionError

-- | Compute the modular exponentiation of base^exponant using
-- algorithms design to avoid side channels and timing measurement
--
-- Modulo need to be odd otherwise the normal fast modular exponentiation
-- is used.
--
-- When used with integer-simple, this function is not different
-- from expFast, and thus provide the same unstudied and dubious
-- timing and side channels claims.
--
-- with GHC 7.10, the powModSecInteger is missing from integer-gmp
-- (which is now integer-gmp2), so is has the same security as old
-- ghc version.
expSafe :: Integer -- ^ base
        -> Integer -- ^ exponant
        -> Integer -- ^ modulo
        -> Integer -- ^ result
#if MIN_VERSION_integer_gmp(0,5,1)
expSafe b e m
#if !(MIN_VERSION_integer_gmp(1,0,0))
    | odd m     = powModSecInteger b e m
#endif
    | otherwise = powModInteger b e m
#else
expSafe = exponentiation
#endif

-- | Compute the modular exponentiation of base^exponant using
-- the fastest algorithm without any consideration for
-- hiding parameters.
--
-- Use this function when all the parameters are public,
-- otherwise 'expSafe' should be prefered.
expFast :: Integer -- ^ base
        -> Integer -- ^ exponant
        -> Integer -- ^ modulo
        -> Integer -- ^ result
expFast =
#if MIN_VERSION_integer_gmp(0,5,1)
    powModInteger
#else
    exponentiation
#endif

-- note on exponentiation: 0^0 is treated as 1 for mimicking the standard library;
-- the mathematic debate is still open on whether or not this is true, but pratically
-- in computer science it shouldn't be useful for anything anyway.

-- | exponentiation_rtl_binary computes modular exponentiation as b^e mod m
-- using the right-to-left binary exponentiation algorithm (HAC 14.79)
exponentiation_rtl_binary :: Integer -> Integer -> Integer -> Integer
#if MIN_VERSION_integer_gmp(0,5,1)
exponentiation_rtl_binary = expSafe
#else
exponentiation_rtl_binary 0 0 m = 1 `mod` m
exponentiation_rtl_binary b e m = loop e b 1
    where sq x          = (x * x) `mod` m
          loop !0 _  !a = a `mod` m
          loop !i !s !a = loop (i `shiftR` 1) (sq s) (if odd i then a * s else a)
#endif

-- | exponentiation computes modular exponentiation as b^e mod m
-- using repetitive squaring.
exponentiation :: Integer -> Integer -> Integer -> Integer
#if MIN_VERSION_integer_gmp(0,5,1)
exponentiation = expSafe
#else
exponentiation b e m
    | b == 1    = b
    | e == 0    = 1
    | e == 1    = b `mod` m
    | even e    = let p = (exponentiation b (e `div` 2) m) `mod` m
                   in (p^(2::Integer)) `mod` m
    | otherwise = (b * exponentiation b (e-1) m) `mod` m
#endif

--{-# DEPRECATED exponantiation_rtl_binary "typo in API name it's called exponentiation_rtl_binary #-}
exponantiation_rtl_binary :: Integer -> Integer -> Integer -> Integer
exponantiation_rtl_binary = exponentiation_rtl_binary

--{-# DEPRECATED exponentiation "typo in API name it's called exponentiation #-}
exponantiation :: Integer -> Integer -> Integer -> Integer
exponantiation = exponentiation

-- | inverse computes the modular inverse as in g^(-1) mod m
inverse :: Integer -> Integer -> Maybe Integer
#if MIN_VERSION_integer_gmp(0,5,1)
inverse g m
    | r == 0    = Nothing
    | otherwise = Just r
  where r = recipModInteger g m
#else
inverse g m
    | d > 1     = Nothing
    | otherwise = Just (x `mod` m)
  where (x,_,d) = gcde g m
#endif

-- | Compute the modular inverse of 2 coprime numbers.
-- This is equivalent to inverse except that the result
-- is known to exists.
--
-- if the numbers are not defined as coprime, this function
-- will raise a CoprimesAssertionError.
inverseCoprimes :: Integer -> Integer -> Integer
inverseCoprimes g m =
    case inverse g m of
        Nothing -> throw CoprimesAssertionError
        Just i  -> i
