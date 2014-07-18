{-# LANGUAGE MagicHash, BangPatterns #-}
-- |
-- Module      : Crypto.Hash.Utils
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash utility for hexadecimal
--
module Crypto.Hash.Utils
    ( toHex
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import GHC.Prim
import GHC.Types
import GHC.Word
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr, castPtr)
import Foreign.Storable (poke, peek)
import Crypto.Hash.Utils.Cpu
import Data.Bits (testBit)

-- | Convert a bytestring to the hexadecimal equivalent
-- using 0123456789abcdef as digit
toHex :: ByteString -> ByteString
toHex (B.PS fp off len) = B.unsafeCreate (len*2) $ \d ->
        withForeignPtr fp $ \s -> start d (s `plusPtr` off)
    where start db sb
            | use32Hex && (len `testBit` 0) == False = loop32 db sb
            | otherwise                              = loop8 db sb
                where end            = sb `plusPtr` len
                      -- write the hex output using 32 bits write.
                      loop32 d s
                         | s == end  = return ()
                         | otherwise = do b1 <- fromIntegral `fmap` (peek s :: IO Word8)
                                          b2 <- fromIntegral `fmap` (peek (s `plusPtr` 1) :: IO Word8)
                                          poke (castPtr d) (to32 b1 b2)
                                          loop32 (d `plusPtr` 4) (s `plusPtr` 2)
                      -- write the hex output 8 bits, 2 at a time
                      loop8 d s
                         | s == end  = return ()
                         | otherwise = do b <- fromIntegral `fmap` (peek s :: IO Word8)
                                          poke d               (r tableHi b)
                                          poke (d `plusPtr` 1) (r tableLo b)
                                          loop8 (d `plusPtr` 2) (s `plusPtr` 1)

          -- little endian version
          to32 (I# i1) (I# i2) = W32# (or# (or# (or# hi2 lo2) hi1) lo1)
            where hi2 = uncheckedShiftL# (indexWord8OffAddr# tableLo i2) 24#
                  lo2 = uncheckedShiftL# (indexWord8OffAddr# tableHi i2) 16#
                  hi1 = uncheckedShiftL# (indexWord8OffAddr# tableLo i1) 8#
                  lo1 = indexWord8OffAddr# tableHi i1

          r :: Addr# -> Int -> Word8
          r table (I# index) = W8# (indexWord8OffAddr# table index)

          !tableLo =
                "0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef"#
          !tableHi =
                "00000000000000001111111111111111\
                \22222222222222223333333333333333\
                \44444444444444445555555555555555\
                \66666666666666667777777777777777\
                \88888888888888889999999999999999\
                \aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb\
                \ccccccccccccccccdddddddddddddddd\
                \eeeeeeeeeeeeeeeeffffffffffffffff"#
