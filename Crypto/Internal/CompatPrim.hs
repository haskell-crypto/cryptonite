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
{-# LANGUAGE MagicHash #-}
module Crypto.Internal.CompatPrim
    ( be32Prim
    , byteswap32Prim
    , booleanPrim
    ) where

import GHC.Prim

#ifdef ARCH_IS_LITTLE_ENDIAN
be32Prim :: Word# -> Word#
be32Prim = byteswap32Prim
#else
be32Prim w = w
#endif

byteswap32Prim :: Word# -> Word#
#if __GLASGOW_HASKELL__ >= 708
byteswap32Prim w = byteSwap32# w
#else
byteswap32Prim w =
    let a =       uncheckedShiftL# w 24#
        b = and# (uncheckedShiftL# w 8#) 0x00ff0000##
        c = and# (uncheckedShiftRL# w 8#) 0x0000ff00##
        d = and# (uncheckedShiftRL# w 24#) 0x000000ff##
     in or# a (or# b (or# c d))
#endif

#if __GLASGOW_HASKELL__ >= 708
booleanPrim :: Int# -> Bool
booleanPrim v = tagToEnum# v
#else
booleanPrim :: Bool -> Bool
booleanPrim b = b
#endif
