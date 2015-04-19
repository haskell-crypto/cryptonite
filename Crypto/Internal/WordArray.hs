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
    , MutableArray32
    , array8
    , array32
    , mutableArray32
    , array64
    , arrayRead8
    , arrayRead32
    , arrayRead64
    , mutableArrayRead32
    , mutableArrayWrite32
    , mutableArrayWriteXor32
    , mutableArray32FromAddrBE
    , mutableArray32Freeze
    ) where

import Data.Word
import Data.Bits (xor)
import Crypto.Internal.Compat
import Crypto.Internal.CompatPrim
import GHC.Prim
import GHC.Types
import GHC.Word

data Array8 = Array8 Addr#

data Array32 = Array32 ByteArray#

data Array64 = Array64 ByteArray#

data MutableArray32 = MutableArray32 (MutableByteArray# RealWorld)

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
                let !st' = writeWord64Array# mb i x st
                 in loop (i +# 1#) st' mb xs
        freezeArray mb st =
            case unsafeFreezeByteArray# mb st of
                (# st', b #) -> (# st', Array64 b #)
{-# NOINLINE array64 #-}

mutableArray32 :: Int -> [Word32] -> IO MutableArray32
mutableArray32 (I# n) l = IO $ \s ->
    case newAlignedPinnedByteArray# (n *# 4#) 4# s of
        (# s', mbarr #) -> loop 0# s' mbarr l
  where
        loop _ st mb [] = (# st, MutableArray32 mb #)
        loop i st mb ((W32# x):xs)
            | booleanPrim (i ==# n) = (# st, MutableArray32 mb #)
            | otherwise =
                let !st' = writeWord32Array# mb i x st
                 in loop (i +# 1#) st' mb xs

mutableArray32FromAddrBE :: Int -> Addr# -> IO MutableArray32
mutableArray32FromAddrBE (I# n) a = IO $ \s ->
    case newAlignedPinnedByteArray# (n *# 4#) 4# s of
        (# s', mbarr #) -> loop 0# s' mbarr
  where
        loop i st mb
            | booleanPrim (i ==# n) = (# st, MutableArray32 mb #)
            | otherwise             =
                let !st' = writeWord32Array# mb i (be32Prim (indexWord32OffAddr# a i)) st
                 in loop (i +# 1#) st' mb

mutableArray32Freeze :: MutableArray32 -> IO Array32
mutableArray32Freeze (MutableArray32 mb) = IO $ \st ->
    case unsafeFreezeByteArray# mb st of
        (# st', b #) -> (# st', Array32 b #)

arrayRead8 :: Array8 -> Int -> Word8
arrayRead8 (Array8 a) (I# o) = W8# (indexWord8OffAddr# a o)
{-# INLINE arrayRead8 #-}

arrayRead32 :: Array32 -> Int -> Word32
arrayRead32 (Array32 b) (I# o) = W32# (indexWord32Array# b o)
{-# INLINE arrayRead32 #-}

arrayRead64 :: Array64 -> Int -> Word64
arrayRead64 (Array64 b) (I# o) = W64# (indexWord64Array# b o)
{-# INLINE arrayRead64 #-}

mutableArrayRead32 :: MutableArray32 -> Int -> IO Word32
mutableArrayRead32 (MutableArray32 m) (I# o) = IO $ \s -> case readWord32Array# m o s of (# s', e #) -> (# s', W32# e #)
{-# INLINE mutableArrayRead32 #-}

mutableArrayWrite32 :: MutableArray32 -> Int -> Word32 -> IO ()
mutableArrayWrite32 (MutableArray32 m) (I# o) (W32# w) = IO $ \s -> let s' = writeWord32Array# m o w s in (# s', () #)
{-# INLINE mutableArrayWrite32 #-}

mutableArrayWriteXor32 :: MutableArray32 -> Int -> Word32 -> IO ()
mutableArrayWriteXor32 m o w =
    mutableArrayRead32 m o >>= \wOld -> mutableArrayWrite32 m o (wOld `xor` w)
{-# INLINE mutableArrayWriteXor32 #-}
