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
module Crypto.Internal.Hex
    ( showHexadecimal
    , toHexadecimal
    ) where

import Crypto.Internal.Compat
import Data.Word
import GHC.Prim
import GHC.Types
import GHC.Word
import Foreign.Storable
import Foreign.Ptr (Ptr)

showHexadecimal :: Ptr Word8 -> Int -> String
showHexadecimal ptr len = loop 0
  where
        loop i
            | i == len  = []
            | otherwise =
                let !(W8# b)     = byteIndex i
                    (# w1, w2 #) = convertByte b
                 in wToChar w1 : wToChar w2 : loop (i+1)

        wToChar :: Word# -> Char
        wToChar w = toEnum (I# (word2Int# w))

        byteIndex :: Int -> Word8
        byteIndex i = unsafeDoIO (peekByteOff ptr i)

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
