-- |
-- Module      : Crypto.Internal.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
module Crypto.Internal.ByteArray
    ( ByteArray(..)
    , byteArrayAllocAndFreeze
    ) where

import Data.SecureMem
import Crypto.Internal.Memory
import Crypto.Internal.Compat
import Foreign.Ptr
import Foreign.ForeignPtr

import Data.ByteString (ByteString)
import qualified Data.ByteString as B (length)
import qualified Data.ByteString.Internal as B

class ByteArray ba where
    byteArrayAlloc  :: Int -> (Ptr p -> IO ()) -> IO ba
    byteArrayLength :: ba -> Int

instance ByteArray Bytes where
    byteArrayAlloc = bytesAlloc
    byteArrayLength = bytesLength

instance ByteArray ByteString where
    byteArrayAlloc sz f = do
        fptr <- B.mallocByteString sz
        withForeignPtr fptr (f . castPtr)
        return $! B.PS fptr 0 sz
    byteArrayLength = B.length

instance ByteArray SecureMem where
    byteArrayAlloc sz f = do
        out <- allocateSecureMem sz
        withSecureMemPtr out (f . castPtr)
        return out
    byteArrayLength = secureMemGetSize

byteArrayAllocAndFreeze :: ByteArray a => Int -> (Ptr p -> IO ()) -> a
byteArrayAllocAndFreeze sz f = unsafeDoIO (byteArrayAlloc sz f)
