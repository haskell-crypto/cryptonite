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
    , jacobi
    ) where

import Control.Exception (throw, Exception)
import Crypto.Number.Basic
import Crypto.Number.Compat

-- | Raised when two numbers are supposed to be coprimes but are not.
data CoprimesAssertionError = CoprimesAssertionError
    deriving (Show)

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

-- | Computes the Jacobi symbol (a/n).
-- 0 ≤ a < n; n ≥ 3 and odd.
--  
-- The Legendre and Jacobi symbols are indistinguishable exactly when the
-- lower argument is an odd prime, in which case they have the same value.
-- 
-- See algorithm 2.149 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
jacobi :: Integer -> Integer -> Maybe Integer
jacobi a n
    | n < 3 || even n  = Nothing
    | a == 0 || a == 1 = Just a
    | n <= a           = jacobi (a `mod` n) n       
    | a < 0            = 
      let b = if n `mod` 4 == 1 then 1 else -1
       in fmap (*b) (jacobi (-a) n)
    | otherwise        =
      let (e, a1) = asPowerOf2AndOdd a
          nMod8   = n `mod` 8
          nMod4   = n `mod` 4
          a1Mod4  = a1 `mod` 4
          s'      = if even e || nMod8 == 1 || nMod8 == 7 then 1 else -1
          s       = if nMod4 == 3 && a1Mod4 == 3 then -s' else s'
          n1      = n `mod` a1
       in if a1 == 1 then Just s
          else fmap (*s) (jacobi n1 a1)
