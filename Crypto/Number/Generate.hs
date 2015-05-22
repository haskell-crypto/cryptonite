-- |
-- Module      : Crypto.Number.Generate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Number.Generate
    ( GenTopPolicy(..)
    , generate
    , generateMax
    , generateBetween
    , generateOfSize
    , generateBits
    ) where

import           Crypto.Internal.Imports
import           Crypto.Number.Basic
import           Crypto.Number.Serialize
import           Crypto.Random.Types
import           Control.Monad (when)
import           Foreign.Ptr
import           Foreign.Storable
import           Data.Bits ((.|.), (.&.), shiftL, shiftR, complement)
import           Crypto.Internal.ByteArray (Bytes, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B


-- | Top bits policy when generating a number
data GenTopPolicy =
      SetHighest    -- ^ set the highest bit
    | SetTwoHighest -- ^ set the two highest bit
    deriving (Show,Eq)

-- | Generate a number for a specific size of bits,
-- and optionaly set bottom and top bits
--
-- If the top bit policy is 'Nothing', then nothing is
-- done on the highest bit (it's whatever the random generator set).
--
-- If @generateOdd is set to 'True', then the number generated
-- is guaranteed to be odd. Otherwise it will be whatever is generated
--
generate :: MonadRandom m
         => Int                -- ^ number of bits
         -> Maybe GenTopPolicy -- ^ top bit policy
         -> Bool               -- ^ force the number to be odd
         -> m Integer
generate bits genTopPolicy generateOdd
    | bits <= 0 = return 0
    | otherwise = os2ip . tweak <$> getRandomBytes bytes
  where
    tweak :: ScrubbedBytes -> ScrubbedBytes
    tweak orig =
        case (genTopPolicy, generateOdd) of
            (Nothing       , False) -> orig
            (Nothing       , True ) -> B.copyAndFreeze orig $ \p -> (p `plusPtr` (bytes-1)) |= 0x1
            (Just topPolicy, _    ) -> B.copyAndFreeze orig $ \p0 -> do
                let p1   = p0 `plusPtr` 1
                    pEnd = p0 `plusPtr` (bytes - 1)
                case topPolicy of
                    SetHighest                -> p0 |= (1 `shiftL` bit)
                    SetTwoHighest | bit == 0  -> do p0 $= 0x1
                                                    p1 |= 0x80
                                  | otherwise -> p0 |= (0x3 `shiftL` (bit - 1))
                p0 &= (complement $ mask)
                when generateOdd (pEnd |= 0x1)

    ($=) :: Ptr Word8 -> Word8 -> IO ()
    ($=) p w = poke p w

    (|=) :: Ptr Word8 -> Word8 -> IO ()
    (|=) p w = peek p >>= \v -> poke p (v .|. w)

    (&=) :: Ptr Word8 -> Word8 -> IO ()
    (&=) p w = peek p >>= \v -> poke p (v .&. w)

    bytes = (bits + 7) `div` 8;
    bit   = (bits - 1) `mod` 8;
    mask  = 0xff `shiftL` (bit + 1);

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

        randomInt nbBytes = os2ipBytes <$> getRandomBytes nbBytes

-- | generate a number between the inclusive bound [low,high].
generateBetween :: MonadRandom m => Integer -> Integer -> m Integer
generateBetween low high = (low +) <$> generateMax (high - low + 1)

-- | generate a positive integer of a specific size in bits.
-- the number of bits need to be multiple of 8. It will always returns
-- an integer that is close to 2^(1+bits/8) by setting the 2 highest bits to 1.
generateOfSize :: MonadRandom m => Int -> m Integer
generateOfSize bits = os2ip . setHighest <$> getRandomBytes (bits `div` 8)
  where
    setHighest :: ScrubbedBytes -> ScrubbedBytes
    setHighest ran = case B.unpack ran of
                        []     -> B.empty
                        (w:ws) -> B.pack ((w .|. 0xc0) : ws)

-- | Generate a number with the specified number of bits
generateBits :: MonadRandom m => Int -> m Integer
generateBits nbBits = modF . os2ipBytes <$> getRandomBytes nbBytes'
  where (nbBytes, strayBits) = nbBits `divMod` 8
        nbBytes' | strayBits == 0 = nbBytes
                 | otherwise      = nbBytes + 1
        modF | strayBits == 0 = id
             | otherwise      = (.&.) (2^nbBits - 1)

os2ipBytes :: Bytes -> Integer
os2ipBytes = os2ip
