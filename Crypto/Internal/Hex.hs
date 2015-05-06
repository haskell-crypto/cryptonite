-- |
-- Module      : Crypto.Internal.Hex
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Hexadecimal escaper
--
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Rank2Types #-}
module Crypto.Internal.Hex
    ( showHexadecimal
    , toHexadecimal
    , toHexadecimal4
    ) where

import Crypto.Internal.Compat
import Crypto.Internal.CompatPrim
import Data.Word
import GHC.Prim
import GHC.Types
import GHC.Word
import Control.Monad
import Foreign.Storable
import Foreign.Ptr (Ptr, plusPtr)

showHexadecimal :: (forall a . (Ptr Word8 -> IO a) -> IO a) -> Int -> String
showHexadecimal withPtr = doChunks 0
  where
        doChunks ofs len
            | len < 4   = doUnique ofs len
            | otherwise = do
                let !(W8# a, W8# b, W8# c, W8# d) = unsafeDoIO $ withPtr (read4 ofs)
                    !(# w1, w2 #) = convertByte a
                    !(# w3, w4 #) = convertByte b
                    !(# w5, w6 #) = convertByte c
                    !(# w7, w8 #) = convertByte d
                 in wToChar w1 : wToChar w2 : wToChar w3 : wToChar w4
                  : wToChar w5 : wToChar w6 : wToChar w7 : wToChar w8
                  : doChunks (ofs + 4) (len - 4)

        doUnique ofs len
            | len == 0  = []
            | otherwise =
                let !(W8# b)     = unsafeDoIO $ withPtr (byteIndex ofs)
                    !(# w1, w2 #) = convertByte b
                 in wToChar w1 : wToChar w2 : doUnique (ofs + 1) (len - 1)

        read4 :: Int -> Ptr Word8 -> IO (Word8, Word8, Word8, Word8)
        read4 ofs p =
            liftM4 (,,,) (byteIndex ofs     p) (byteIndex (ofs+1) p)
                         (byteIndex (ofs+2) p) (byteIndex (ofs+3) p)

        wToChar :: Word# -> Char
        wToChar w = toEnum (I# (word2Int# w))

        byteIndex :: Int -> Ptr Word8 -> IO Word8
        byteIndex i p = peekByteOff p i

toHexadecimal :: Ptr Word8 -> Ptr Word8 -> Int -> IO ()
toHexadecimal bout bin n = loop 0
  where loop i
            | i == n  = return ()
            | otherwise = do
                (W8# w) <- peekByteOff bin i
                let (# w1, w2 #) = convertByte w
                pokeByteOff bout (i * 2)     (W8# w1)
                pokeByteOff bout (i * 2 + 1) (W8# w2)
                loop (i+1)

-- | convert to hexadecimal going 2 by 2
--
-- experimental. untested
toHexadecimal4 :: Ptr Word32 -> Ptr Word8 -> Int -> IO ()
toHexadecimal4 bout bin n = loop 0
  where loop i
            | i == n = return ()
            | otherwise = do
                (W8# w1) <- peekByteOff bin i
                (W8# w2) <- peekByteOff bin (i+1)
                let r = W32# (convertByte4 w1 w2)
                poke (bout `plusPtr` (i * 2)) r
                loop (i+2)

convertByte4 :: Word# -> Word# -> Word#
convertByte4 a b = convert4To32 (# b2, b1, a2, a1 #)
  where
        !(# a1, a2 #) = convertByte a
        !(# b1, b2 #) = convertByte b

convertByte :: Word# -> (# Word#, Word# #)
convertByte b = (# r tableHi b, r tableLo b #)
  where
        r :: Addr# -> Word# -> Word#
        r table index = indexWord8OffAddr# table (word2Int# index)

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
{-# INLINE convertByte #-}
