-- |
-- Module      : Crypto.Internal.CompatPrim
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
module Crypto.Internal.CompatPrim
    ( be32Prim
    , le32Prim
    , byteswap32Prim
    , booleanPrim
    , convert4To32
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

-- | combine 4 word8 [a,b,c,d] to a word32 representing [a,b,c,d]
convert4To32 :: (# Word#, Word#, Word#, Word# #) -> Word#
convert4To32 (# a, b, c, d #) = or# (or# c1 c2) (or# c3 c4)
  where
#ifdef ARCH_IS_LITTLE_ENDIAN
        !c1 = uncheckedShiftL# a 24#
        !c2 = uncheckedShiftL# b 16#
        !c3 = uncheckedShiftL# c 8#
        !c4 = d
#else
        !c1 = uncheckedShiftL# d 24#
        !c2 = uncheckedShiftL# c 16#
        !c3 = uncheckedShiftL# b 8#
        !c4 = a
#endif

#if __GLASGOW_HASKELL__ >= 708
booleanPrim :: Int# -> Bool
booleanPrim v = tagToEnum# v
#else
booleanPrim :: Bool -> Bool
booleanPrim b = b
#endif
