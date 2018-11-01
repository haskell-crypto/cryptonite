{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Crypto.Number.ModArithmetic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.ModArithmetic
    (
    -- * Exponentiation
      expSafe
    , expFast
    -- * Inverse computing
    , inverse
    , inverseCoprimes
    ) where

import Control.Exception (throw, Exception)
import Data.Typeable
import Crypto.Number.Basic
import Crypto.Number.Compat

-- | Raised when two numbers are supposed to be coprimes but are not.
data CoprimesAssertionError = CoprimesAssertionError
    deriving (Show,Typeable)

instance Exception CoprimesAssertionError

-- | Compute the modular exponentiation of base^exponent using
-- algorithms design to avoid side channels and timing measurement
--
-- Modulo need to be odd otherwise the normal fast modular exponentiation
-- is used.
--
-- When used with integer-simple, this function is not different
-- from expFast, and thus provide the same unstudied and dubious
-- timing and side channels claims.
--
-- Before GHC 8.4.2, powModSecInteger is missing from integer-gmp,
-- so expSafe has the same security as expFast.
expSafe :: Integer -- ^ base
        -> Integer -- ^ exponent
        -> Integer -- ^ modulo
        -> Integer -- ^ result
expSafe b e m
    | odd m     = gmpPowModSecInteger b e m `onGmpUnsupported`
                  (gmpPowModInteger b e m   `onGmpUnsupported`
                  exponentiation b e m)
    | otherwise = gmpPowModInteger b e m    `onGmpUnsupported`
                  exponentiation b e m

-- | Compute the modular exponentiation of base^exponent using
-- the fastest algorithm without any consideration for
-- hiding parameters.
--
-- Use this function when all the parameters are public,
-- otherwise 'expSafe' should be prefered.
expFast :: Integer -- ^ base
        -> Integer -- ^ exponent
        -> Integer -- ^ modulo
        -> Integer -- ^ result
expFast b e m = gmpPowModInteger b e m `onGmpUnsupported` exponentiation b e m

-- | @exponentiation@ computes modular exponentiation as /b^e mod m/
-- using repetitive squaring.
exponentiation :: Integer -> Integer -> Integer -> Integer
exponentiation b e m
    | b == 1    = b
    | e == 0    = 1
    | e == 1    = b `mod` m
    | even e    = let p = (exponentiation b (e `div` 2) m) `mod` m
                   in (p^(2::Integer)) `mod` m
    | otherwise = (b * exponentiation b (e-1) m) `mod` m

-- | @inverse@ computes the modular inverse as in /g^(-1) mod m/.
inverse :: Integer -> Integer -> Maybe Integer
inverse g m = gmpInverse g m `onGmpUnsupported` v
  where
    v
        | d > 1     = Nothing
        | otherwise = Just (x `mod` m)
    (x,_,d) = gcde g m

-- | Compute the modular inverse of two coprime numbers.
-- This is equivalent to inverse except that the result
-- is known to exists.
--
-- If the numbers are not defined as coprime, this function
-- will raise a 'CoprimesAssertionError'.
inverseCoprimes :: Integer -> Integer -> Integer
inverseCoprimes g m =
    case inverse g m of
        Nothing -> throw CoprimesAssertionError
        Just i  -> i
