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
    ) where

import Crypto.Internal.Compat
import Data.Word
import GHC.Prim
import GHC.Types
import Foreign.Storable
import Foreign.Ptr (Ptr)

showHexadecimal :: Ptr Word8 -> Int -> String
showHexadecimal ptr len = loop 0
  where
        loop i
            | i == len  = []
            | otherwise =
                let b = fromIntegral (byteIndex i)
                 in toEnum (r tableHi b) : toEnum (r tableLo b) : loop (i+1)

        byteIndex :: Int -> Word8
        byteIndex i = unsafeDoIO (peekByteOff ptr i)

        r :: Addr# -> Int -> Int
        r table (I# index) = I# (word2Int# (indexWord8OffAddr# table index))

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
