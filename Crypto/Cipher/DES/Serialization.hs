-- |
-- Module      : Crypto.Cipher.DES.Serialization
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- basic routine to convert between W64 and bytestring for DES.
--
module Crypto.Cipher.DES.Serialization
    ( toBS
    ) where

import qualified Data.ByteString as B
import Crypto.Cipher.DES.Primitive (Block(..))

import Crypto.Internal.ByteArray
import Crypto.Internal.Endian

import Foreign.Storable

toBS :: Block -> B.ByteString
toBS (Block w) = byteArrayAllocAndFreeze 8 $ \ptr -> poke ptr (toBE64 w)
