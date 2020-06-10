-- |
-- Module      : Crypto.Internal.Endian
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE CPP #-}
module Crypto.Internal.Endian
    ( fromBE64, toBE64
    , fromLE64, toLE64
    , fromLE32, toLE32
    ) where

import Crypto.Internal.Compat (byteSwap64)
import Data.Word (Word32, Word64)

#ifdef ARCH_IS_LITTLE_ENDIAN
fromLE64 :: Word64 -> Word64
fromLE64 = id

toLE64 :: Word64 -> Word64
toLE64 = id

fromBE64 :: Word64 -> Word64
fromBE64 = byteSwap64

toBE64 :: Word64 -> Word64
toBE64 = byteSwap64

fromLE32 :: Word32 -> Word32
fromLE32 = id

toLE32 :: Word32 -> Word32
toLE32 = id
#else
fromLE64 :: Word64 -> Word64
fromLE64 = byteSwap64

toLE64 :: Word64 -> Word64
toLE64 = byteSwap64

fromBE64 :: Word64 -> Word64
fromBE64 = id

toBE64 :: Word64 -> Word64
toBE64 = id

fromLE32 :: Word32 -> Word32
fromLE32 = byteSwap32

toLE32 :: Word32 -> Word32
toLE32 = byteSwap32
#endif
