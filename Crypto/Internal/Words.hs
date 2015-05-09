-- |
-- Module      : Crypto.Internal.Words
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Extra Word size
--
module Crypto.Internal.Words
    ( Word128(..)
    , w64to32
    , w32to64
    ) where

import Data.Word
import Data.Bits
import Data.Memory.ExtendedWords

w64to32 :: Word64 -> (Word32, Word32)
w64to32 w = (fromIntegral (w `shiftR` 32), fromIntegral w)

w32to64 :: (Word32, Word32) -> Word64
w32to64 (x1, x2) = ((fromIntegral x1) `shiftL` 32) .|. (fromIntegral x2)
