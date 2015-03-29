-- |
-- Module      : Crypto.Number.Prime
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif
#if MIN_VERSION_integer_gmp(0,5,1)
{-# LANGUAGE MagicHash #-}
#endif
module Crypto.Number.Prime
    (
      generatePrime
    , generateSafePrime
    , isProbablyPrime
    , findPrimeFrom
    , findPrimeFromWith
    , primalityTestMillerRabin
    , primalityTestNaive
    , primalityTestFermat
    , isCoprime
    ) where

import Control.Applicative

import Crypto.Number.Generate
import Crypto.Number.Basic (sqrti, gcde_binary)
import Crypto.Number.ModArithmetic (exponantiation)
import Crypto.Random.Types

#if MIN_VERSION_integer_gmp(0,5,1)
import GHC.Integer.GMP.Internals
import GHC.Base
#else
import Data.Bits
#endif

-- | returns if the number is probably prime.
-- first a list of small primes are implicitely tested for divisibility,
-- then a fermat primality test is used with arbitrary numbers and
-- then the Miller Rabin algorithm is used with an accuracy of 30 recursions
isProbablyPrime :: MonadRandom m => Integer -> m Bool
isProbablyPrime !n
    | any (\p -> p `divides` n) (filter (< n) firstPrimes) = return False
    | primalityTestFermat 50 (n`div`2) n                   = primalityTestMillerRabin 30 n
    | otherwise                                            = return False

-- | generate a prime number of the required bitsize
generatePrime :: MonadRandom m => Int -> m Integer
generatePrime bits = do
    sp <- generateOfSize bits
    findPrimeFrom sp

-- | generate a prime number of the form 2p+1 where p is also prime.
-- it is also knowed as a Sophie Germaine prime or safe prime.
--
-- The number of safe prime is significantly smaller to the number of prime,
-- as such it shouldn't be used if this number is supposed to be kept safe.
generateSafePrime :: MonadRandom m => Int -> m Integer
generateSafePrime bits = do
    sp <- generateOfSize bits
    p  <- findPrimeFromWith (\i -> isProbablyPrime (2*i+1)) (sp `div` 2)
    return (2*p+1)

-- | find a prime from a starting point where the property hold.
findPrimeFromWith :: MonadRandom m => (Integer -> m Bool) -> Integer -> m Integer
findPrimeFromWith prop !n
    | even n        = findPrimeFromWith prop (n+1)
    | otherwise     = do
        primed <- isProbablyPrime n
        if not primed
            then findPrimeFromWith prop (n+2)
            else do
                validate <- prop n
                if validate
                    then return n
                    else findPrimeFromWith prop (n+2)

-- | find a prime from a starting point with no specific property.
findPrimeFrom :: MonadRandom m => Integer -> m Integer
findPrimeFrom n =
#if MIN_VERSION_integer_gmp(0,5,1)
    return $ nextPrimeInteger n
#else
    findPrimeFromWith (\_ -> return True) n
#endif

-- | Miller Rabin algorithm return if the number is probably prime or composite.
-- the tries parameter is the number of recursion, that determines the accuracy of the test.
primalityTestMillerRabin :: MonadRandom m => Int -> Integer -> m Bool
#if MIN_VERSION_integer_gmp(0,5,1)
primalityTestMillerRabin (I# tries) !n =
    case testPrimeInteger n tries of
        0# -> return False
        _  -> return True
#else
primalityTestMillerRabin tries !n
    | n <= 3     = error "Miller-Rabin requires tested value to be > 3"
    | even n     = return False
    | tries <= 0 = error "Miller-Rabin tries need to be > 0"
    | otherwise  = loop <$> generateTries tries
  where
    !nm1 = n-1
    !nm2 = n-2

    (!s,!d) = (factorise 0 nm1)

    generateTries 0 = return []
    generateTries t = do
        v  <- generateBetween 2 nm2
        vs <- generateTries (t-1)
        return (v:vs)

    -- factorise n-1 into the form 2^s*d
    factorise :: Integer -> Integer -> (Integer, Integer)
    factorise !si !vi
        | vi `testBit` 0 = (si, vi)
        | otherwise     = factorise (si+1) (vi `shiftR` 1) -- probably faster to not shift v continously, but just once.
    expmod = exponantiation

    -- when iteration reach zero, we have a probable prime
    loop []     = True
    loop (w:ws) = let x = expmod w d n
                   in if x == (1 :: Integer) || x == nm1
                          then loop ws
                          else loop' ws ((x*x) `mod` n) 1

    -- loop from 1 to s-1. if we reach the end then it's composite
    loop' ws !x2 !r
        | r == s    = False
        | x2 == 1   = False
        | x2 /= nm1 = loop' ws ((x2*x2) `mod` n) (r+1)
        | otherwise = loop ws
#endif

{-
    n < z -> witness to test
              1373653 [2,3]
              9080191 [31,73]
              4759123141 [2,7,61]
              2152302898747 [2,3,5,7,11]
              3474749660383 [2,3,5,7,11,13]
              341550071728321 [2,3,5,7,11,13,17]
-}

-- | Probabilitic Test using Fermat primility test.
-- Beware of Carmichael numbers that are Fermat liars, i.e. this test
-- is useless for them. always combines with some other test.
primalityTestFermat :: Int -- ^ number of iterations of the algorithm
                    -> Integer -- ^ starting a
                    -> Integer -- ^ number to test for primality
                    -> Bool
primalityTestFermat n a p = and $ map expTest [a..(a+fromIntegral n)]
    where !pm1 = p-1
          expTest i = exponantiation i pm1 p == 1

-- | Test naively is integer is prime.
-- while naive, we skip even number and stop iteration at i > sqrt(n)
primalityTestNaive :: Integer -> Bool
primalityTestNaive n
    | n <= 1    = False
    | n == 2    = True
    | even n    = False
    | otherwise = search 3
        where !ubound = snd $ sqrti n
              search !i
                  | i > ubound    = True
                  | i `divides` n = False
                  | otherwise     = search (i+2)

-- | Test is two integer are coprime to each other
isCoprime :: Integer -> Integer -> Bool
isCoprime m n = case gcde_binary m n of (_,_,d) -> d == 1

-- | list of the first primes till 2903..
firstPrimes :: [Integer]
firstPrimes =
    [ 2    , 3    , 5    , 7    , 11   , 13   , 17   , 19   , 23   , 29
    , 31   , 37   , 41   , 43   , 47   , 53   , 59   , 61   , 67   , 71
    , 73   , 79   , 83   , 89   , 97   , 101  , 103  , 107  , 109  , 113
    , 127  , 131  , 137  , 139  , 149  , 151  , 157  , 163  , 167  , 173
    , 179  , 181  , 191  , 193  , 197  , 199  , 211  , 223  , 227  , 229
    , 233  , 239  , 241  , 251  , 257  , 263  , 269  , 271  , 277  , 281
    , 283  , 293  , 307  , 311  , 313  , 317  , 331  , 337  , 347  , 349
    , 353  , 359  , 367  , 373  , 379  , 383  , 389  , 397  , 401  , 409
    , 419  , 421  , 431  , 433  , 439  , 443  , 449  , 457  , 461  , 463
    , 467  , 479  , 487  , 491  , 499  , 503  , 509  , 521  , 523  , 541
    , 547  , 557  , 563  , 569  , 571  , 577  , 587  , 593  , 599  , 601
    , 607  , 613  , 617  , 619  , 631  , 641  , 643  , 647  , 653  , 659
    , 661  , 673  , 677  , 683  , 691  , 701  , 709  , 719  , 727  , 733
    , 739  , 743  , 751  , 757  , 761  , 769  , 773  , 787  , 797  , 809
    , 811  , 821  , 823  , 827  , 829  , 839  , 853  , 857  , 859  , 863
    , 877  , 881  , 883  , 887  , 907  , 911  , 919  , 929  , 937  , 941
    , 947  , 953  , 967  , 971  , 977  , 983  , 991  , 997  , 1009 , 1013
    , 1019 , 1021 , 1031 , 1033 , 1039 , 1049 , 1051 , 1061 , 1063 , 1069
    , 1087 , 1091 , 1093 , 1097 , 1103 , 1109 , 1117 , 1123 , 1129 , 1151
    , 1153 , 1163 , 1171 , 1181 , 1187 , 1193 , 1201 , 1213 , 1217 , 1223
    , 1229 , 1231 , 1237 , 1249 , 1259 , 1277 , 1279 , 1283 , 1289 , 1291
    , 1297 , 1301 , 1303 , 1307 , 1319 , 1321 , 1327 , 1361 , 1367 , 1373
    , 1381 , 1399 , 1409 , 1423 , 1427 , 1429 , 1433 , 1439 , 1447 , 1451
    , 1453 , 1459 , 1471 , 1481 , 1483 , 1487 , 1489 , 1493 , 1499 , 1511
    , 1523 , 1531 , 1543 , 1549 , 1553 , 1559 , 1567 , 1571 , 1579 , 1583
    , 1597 , 1601 , 1607 , 1609 , 1613 , 1619 , 1621 , 1627 , 1637 , 1657
    , 1663 , 1667 , 1669 , 1693 , 1697 , 1699 , 1709 , 1721 , 1723 , 1733
    , 1741 , 1747 , 1753 , 1759 , 1777 , 1783 , 1787 , 1789 , 1801 , 1811
    , 1823 , 1831 , 1847 , 1861 , 1867 , 1871 , 1873 , 1877 , 1879 , 1889
    , 1901 , 1907 , 1913 , 1931 , 1933 , 1949 , 1951 , 1973 , 1979 , 1987
    , 1993 , 1997 , 1999 , 2003 , 2011 , 2017 , 2027 , 2029 , 2039 , 2053
    , 2063 , 2069 , 2081 , 2083 , 2087 , 2089 , 2099 , 2111 , 2113 , 2129
    , 2131 , 2137 , 2141 , 2143 , 2153 , 2161 , 2179 , 2203 , 2207 , 2213
    , 2221 , 2237 , 2239 , 2243 , 2251 , 2267 , 2269 , 2273 , 2281 , 2287
    , 2293 , 2297 , 2309 , 2311 , 2333 , 2339 , 2341 , 2347 , 2351 , 2357
    , 2371 , 2377 , 2381 , 2383 , 2389 , 2393 , 2399 , 2411 , 2417 , 2423
    , 2437 , 2441 , 2447 , 2459 , 2467 , 2473 , 2477 , 2503 , 2521 , 2531
    , 2539 , 2543 , 2549 , 2551 , 2557 , 2579 , 2591 , 2593 , 2609 , 2617
    , 2621 , 2633 , 2647 , 2657 , 2659 , 2663 , 2671 , 2677 , 2683 , 2687
    , 2689 , 2693 , 2699 , 2707 , 2711 , 2713 , 2719 , 2729 , 2731 , 2741
    , 2749 , 2753 , 2767 , 2777 , 2789 , 2791 , 2797 , 2801 , 2803 , 2819
    , 2833 , 2837 , 2843 , 2851 , 2857 , 2861 , 2879 , 2887 , 2897 , 2903
    ]

{-# INLINE divides #-}
divides :: Integer -> Integer -> Bool
divides i n = n `mod` i == 0
