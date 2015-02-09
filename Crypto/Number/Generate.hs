-- |
-- Module      : Crypto.Number.Generate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.Generate
    ( {-generateMax
    , generateBetween
    , generateOfSize
    , generateBits-}
    ) where

import Crypto.Number.Basic
import Crypto.Number.Serialize
import qualified Data.ByteString as B
import Data.Bits ((.|.), (.&.), shiftR)

{-
-- | generate a positive integer x, s.t. 0 <= x < m
generateMax :: CPRG g => g -> Integer -> (Integer, g)
generateMax rng 1 = (0, rng)
generateMax rng m
    | (result' >= m) = generateMax rng' m
    | otherwise      = (result', rng')
  where
        bytesLength   = lengthBytes m
        bitsLength    = (log2 (m-1) + 1)
        bitsPoppedOff = 8 - (bitsLength `mod` 8)
        randomInt bytes = withRandomBytes rng bytes $ \bs -> os2ip bs

        (result, rng') = randomInt bytesLength
        result' = result `shiftR` bitsPoppedOff

-- | generate a number between the inclusive bound [low,high].
generateBetween :: CPRG g => g -> Integer -> Integer -> (Integer, g)
generateBetween rng low high = (low + v, rng')
    where (v, rng') = generateMax rng (high - low + 1)

-- | generate a positive integer of a specific size in bits.
-- the number of bits need to be multiple of 8. It will always returns
-- an integer that is close to 2^(1+bits/8) by setting the 2 highest bits to 1.
generateOfSize :: CPRG g => g -> Int -> (Integer, g)
generateOfSize rng bits = withRandomBytes rng (bits `div` 8) $ \bs ->
    os2ip $ snd $ B.mapAccumL (\acc w -> (0, w .|. acc)) 0xc0 bs

-- | Generate a number with the specified number of bits
generateBits :: CPRG g => g -> Int -> (Integer, g)
generateBits rng nbBits = withRandomBytes rng nbBytes' $ \bs -> modF (os2ip bs)
  where (nbBytes, strayBits) = nbBits `divMod` 8
        nbBytes' | strayBits == 0 = nbBytes
                 | otherwise      = nbBytes + 1
        modF | strayBits == 0 = id
             | otherwise      = (.&.) (2^nbBits - 1)
-}
