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
    , empty
    , byteArrayCopyAndFreeze
    , byteArraySplit
    , byteArrayXor
    , byteArrayConcat
    ) where

import Data.Word
import Data.SecureMem
import Crypto.Internal.Memory
import Crypto.Internal.Compat
import Crypto.Internal.Bytes (bufXor, bufCopy)
import Foreign.Ptr
import Foreign.ForeignPtr
import Data.ByteString (ByteString)
import qualified Data.ByteString as B (length)
import qualified Data.ByteString.Internal as B

class ByteArray ba where
    byteArrayAlloc  :: Int -> (Ptr p -> IO ()) -> IO ba
    byteArrayLength :: ba -> Int
    withByteArray   :: ba -> (Ptr p -> IO a) -> IO a

instance ByteArray Bytes where
    byteArrayAlloc  = bytesAlloc
    byteArrayLength = bytesLength
    withByteArray   = withBytes

instance ByteArray ByteString where
    byteArrayAlloc sz f = do
        fptr <- B.mallocByteString sz
        withForeignPtr fptr (f . castPtr)
        return $! B.PS fptr 0 sz
    byteArrayLength = B.length
    withByteArray b f = withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
      where (fptr, off, _) = B.toForeignPtr b

instance ByteArray SecureMem where
    byteArrayAlloc sz f = do
        out <- allocateSecureMem sz
        withSecureMemPtr out (f . castPtr)
        return out
    byteArrayLength = secureMemGetSize
    withByteArray b f = withSecureMemPtr b (f . castPtr)

byteArrayAllocAndFreeze :: ByteArray a => Int -> (Ptr p -> IO ()) -> a
byteArrayAllocAndFreeze sz f = unsafeDoIO (byteArrayAlloc sz f)

empty :: ByteArray a => a
empty = unsafeDoIO (byteArrayAlloc 0 $ \_ -> return ())

-- | Create a xor of bytes between a and b.
--
-- the returns byte array is the size of the smallest input.
byteArrayXor :: (ByteArray a, ByteArray b, ByteArray c) => a -> b -> c
byteArrayXor a b =
    byteArrayAllocAndFreeze n $ \pc ->
    withByteArray a           $ \pa ->
    withByteArray b           $ \pb ->
        bufXor pc pa pb n
  where
        n  = min la lb
        la = byteArrayLength a
        lb = byteArrayLength b

byteArraySplit :: ByteArray bs => Int -> bs -> (bs, bs)
byteArraySplit n bs
    | n <= 0    = (empty, bs)
    | n >= len  = (bs, empty)
    | otherwise = unsafeDoIO $ do
        withByteArray bs $ \p -> do
            b1 <- byteArrayAlloc n $ \r -> bufCopy r p n
            b2 <- byteArrayAlloc (len - n) $ \r -> bufCopy r (p `plusPtr` n) (len - n)
            return (b1, b2)
  where len = byteArrayLength bs

byteArrayConcat :: ByteArray bs => [bs] -> bs
byteArrayConcat []    = empty
byteArrayConcat allBs = byteArrayAllocAndFreeze total (loop allBs)
  where
        total = sum $ map byteArrayLength allBs

        loop []     _   = return ()
        loop (b:bs) dst = do
            let sz = byteArrayLength b
            withByteArray b $ \p -> bufCopy dst p sz
            loop bs (dst `plusPtr` sz)

byteArrayCopyAndFreeze :: ByteArray bs => bs -> (Ptr p -> IO ()) -> bs
byteArrayCopyAndFreeze bs f =
    byteArrayAllocAndFreeze (byteArrayLength bs) $ \d -> do
        withByteArray bs $ \s -> bufCopy d s (byteArrayLength bs)
        f (castPtr d)
