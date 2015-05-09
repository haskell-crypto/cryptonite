-- |
-- Module      : Data.Memory.Internal.CompatPrim
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Compat
--
-- This module try to keep all the difference between versions of ghc primitive
-- or other needed packages, so that modules don't need to use CPP.
--
-- Note that MagicHash and CPP conflicts in places, making it "more interesting"
-- to write compat code for primitives
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
module Data.Memory.Internal.CompatPrim
    ( be32Prim
    , le32Prim
    , byteswap32Prim
    , booleanPrim
    , eitherDivideBy8#
    ) where

import GHC.Prim

-- | byteswap Word# to or from Big Endian
--
-- on a big endian machine, this function is a nop.
be32Prim :: Word# -> Word#
#ifdef ARCH_IS_LITTLE_ENDIAN
be32Prim = byteswap32Prim
#else
be32Prim w = w
#endif

-- | byteswap Word# to or from Little Endian
--
-- on a little endian machine, this function is a nop.
le32Prim :: Word# -> Word#
#ifdef ARCH_IS_LITTLE_ENDIAN
le32Prim w = w
#else
le32Prim = byteswap32Prim
#endif

byteswap32Prim :: Word# -> Word#
#if __GLASGOW_HASKELL__ >= 708
byteswap32Prim w = byteSwap32# w
#else
byteswap32Prim w =
    let !a =       uncheckedShiftL# w 24#
        !b = and# (uncheckedShiftL# w 8#) 0x00ff0000##
        !c = and# (uncheckedShiftRL# w 8#) 0x0000ff00##
        !d = and# (uncheckedShiftRL# w 24#) 0x000000ff##
     in or# a (or# b (or# c d))
#endif

#if __GLASGOW_HASKELL__ >= 708
booleanPrim :: Int# -> Bool
booleanPrim v = tagToEnum# v
#else
booleanPrim :: Bool -> Bool
booleanPrim b = b
#endif

-- | Apply or or another function if 8 divides the number of bytes
eitherDivideBy8# :: Int#        -- ^ number of bytes
                 -> (Int# -> a) -- ^ if it divided by 8, the argument is the number of 8 bytes words
                 -> (Int# -> a) -- ^ if it doesn't, just the number of bytes
                 -> a
#if __GLASGOW_HASKELL__ >= 740
eitherDivideBy8# v f8 f1 =
    let !(# q, r #) = quotRemInt v 8#
     in if booleanPrim (r ==# 0)
            then f8 q
            else f1 v
#else
eitherDivideBy8# v f8 f1 =
    if booleanPrim ((remInt# v 8#) ==# 0#)
        then f8 (quotInt# v 8#)
        else f1 v
#endif
