-- |
-- Module      : Crypto.Internal.Compat
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Small and self contained array representation
-- with limited safety for internal use.
--
-- the array produced should never be exposed to the user directly
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
module Crypto.Internal.WordArray
    ( Array8
    , Array32
    , Array64
    , array8
    , array32
    , array64
    , arrayRead8
    , arrayRead32
    , arrayRead64
    ) where

import Data.Word
import Crypto.Internal.Compat
import GHC.Prim
import GHC.Types
import GHC.Word

data Array8 = Array8 Addr#

data Array32 = Array32 ByteArray#

data Array64 = Array64 ByteArray#

array8 :: Addr# -> Array8
array8 = Array8

array32 :: Int -> [Word32] -> Array32
array32 (I# n) l = unsafeDoIO $ IO $ \s ->
    case newAlignedPinnedByteArray# (n *# 4#) 4# s of
        (# s', mbarr #) -> loop 0# s' mbarr l
  where
        loop _ st mb [] = freezeArray mb st
        loop i st mb ((W32# x):xs)
            | booleanPrim (i ==# n) = freezeArray mb st
            | otherwise =
                let st' = writeWord32Array# mb i x st
                 in loop (i +# 1#) st' mb xs
        freezeArray mb st =
            case unsafeFreezeByteArray# mb st of
                (# st', b #) -> (# st', Array32 b #)
{-# NOINLINE array32 #-}

array64 :: Int -> [Word64] -> Array64
array64 (I# n) l = unsafeDoIO $ IO $ \s ->
    case newAlignedPinnedByteArray# (n *# 8#) 8# s of
        (# s', mbarr #) -> loop 0# s' mbarr l
  where
        loop _ st mb [] = freezeArray mb st
        loop i st mb ((W64# x):xs)
            | booleanPrim (i ==# n) = freezeArray mb st
            | otherwise =
                let st' = writeWord64Array# mb i x st
                 in loop (i +# 1#) st' mb xs
        freezeArray mb st =
            case unsafeFreezeByteArray# mb st of
                (# st', b #) -> (# st', Array64 b #)
{-# NOINLINE array64 #-}

arrayRead8 :: Array8 -> Int -> Word8
arrayRead8 (Array8 a) (I# o) = W8# (indexWord8OffAddr# a o)
{-# INLINE arrayRead8 #-}

arrayRead32 :: Array32 -> Int -> Word32
arrayRead32 (Array32 b) (I# o) = W32# (indexWord32Array# b o)
{-# INLINE arrayRead32 #-}

arrayRead64 :: Array64 -> Int -> Word64
arrayRead64 (Array64 b) (I# o) = W64# (indexWord64Array# b o)
{-# INLINE arrayRead64 #-}
