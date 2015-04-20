-- |
-- Module      : Crypto.Number.Generate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.Generate
    ( generateMax
    , generateBetween
    , generateOfSize
    , generateBits
    ) where

import           Crypto.Internal.Imports
import           Crypto.Number.Basic
import           Crypto.Number.Serialize
import           Crypto.Random.Types
import qualified Data.ByteString as B
import           Data.Bits ((.|.), (.&.), shiftR)


-- | generate a positive integer x, s.t. 0 <= x < m
generateMax :: MonadRandom m => Integer -> m Integer
generateMax 1 = return 0
generateMax m
    | m <= 0    = error "negative value for generateMax"
    | otherwise = do
        result <- randomInt bytesLength
        let result' = result `shiftR` bitsPoppedOff
        if result' >= m
            then generateMax m
            else return result'
  where
        bytesLength   = lengthBytes m
        bitsLength    = log2 (m-1) + 1
        bitsPoppedOff = 8 - (bitsLength `mod` 8)

        randomInt nbBytes = os2ip <$> getRandomBytes nbBytes

-- | generate a number between the inclusive bound [low,high].
generateBetween :: MonadRandom m => Integer -> Integer -> m Integer
generateBetween low high = (low +) <$> generateMax (high - low + 1)

-- | generate a positive integer of a specific size in bits.
-- the number of bits need to be multiple of 8. It will always returns
-- an integer that is close to 2^(1+bits/8) by setting the 2 highest bits to 1.
generateOfSize :: MonadRandom m => Int -> m Integer
generateOfSize bits = unmarshall <$> getRandomBytes (bits `div` 8)
  where
    unmarshall bs = os2ip $ snd $ B.mapAccumL (\acc w -> (0, w .|. acc)) 0xc0 bs

-- | Generate a number with the specified number of bits
generateBits :: MonadRandom m => Int -> m Integer
generateBits nbBits = modF . os2ip <$> getRandomBytes nbBytes'
  where (nbBytes, strayBits) = nbBits `divMod` 8
        nbBytes' | strayBits == 0 = nbBytes
                 | otherwise      = nbBytes + 1
        modF | strayBits == 0 = id
             | otherwise      = (.&.) (2^nbBits - 1)
