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
    , ByteArrayAccess(..)
    , byteArrayAllocAndFreeze
    , empty
    , byteArrayCopyAndFreeze
    , byteArraySplit
    , byteArrayXor
    , byteArrayConcat
    , byteArrayToBS
    , byteArrayFromBS
    , byteArrayToW64BE
    ) where

import Control.Applicative ((<$>))
import Data.Word
import Data.SecureMem
import Crypto.Internal.Memory
import Crypto.Internal.Compat
import Crypto.Internal.Endian
import Crypto.Internal.Bytes (bufXor, bufCopy)
import Foreign.Ptr
import Foreign.Storable
import Foreign.ForeignPtr
import Data.ByteString (ByteString)
import qualified Data.ByteString as B (length)
import qualified Data.ByteString.Internal as B

class ByteArrayAccess ba where
    byteArrayLength :: ba -> Int
    withByteArray   :: ba -> (Ptr p -> IO a) -> IO a

class ByteArrayAccess ba => ByteArray ba where
    byteArrayAlloc  :: Int -> (Ptr p -> IO ()) -> IO ba

instance ByteArrayAccess Bytes where
    byteArrayLength = bytesLength
    withByteArray   = withBytes
instance ByteArray Bytes where
    byteArrayAlloc  = bytesAlloc

instance ByteArrayAccess ByteString where
    byteArrayLength = B.length
    withByteArray b f = withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
      where (fptr, off, _) = B.toForeignPtr b
instance ByteArray ByteString where
    byteArrayAlloc sz f = do
        fptr <- B.mallocByteString sz
        withForeignPtr fptr (f . castPtr)
        return $! B.PS fptr 0 sz

instance ByteArrayAccess SecureMem where
    byteArrayLength = secureMemGetSize
    withByteArray b f = withSecureMemPtr b (f . castPtr)
instance ByteArray SecureMem where
    byteArrayAlloc sz f = do
        out <- allocateSecureMem sz
        withSecureMemPtr out (f . castPtr)
        return out

byteArrayAllocAndFreeze :: ByteArray a => Int -> (Ptr p -> IO ()) -> a
byteArrayAllocAndFreeze sz f = unsafeDoIO (byteArrayAlloc sz f)

empty :: ByteArray a => a
empty = unsafeDoIO (byteArrayAlloc 0 $ \_ -> return ())

-- | Create a xor of bytes between a and b.
--
-- the returns byte array is the size of the smallest input.
byteArrayXor :: (ByteArrayAccess a, ByteArrayAccess b, ByteArray c) => a -> b -> c
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

byteArrayCopyAndFreeze :: (ByteArray bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO ()) -> bs2
byteArrayCopyAndFreeze bs f =
    byteArrayAllocAndFreeze (byteArrayLength bs) $ \d -> do
        withByteArray bs $ \s -> bufCopy d s (byteArrayLength bs)
        f (castPtr d)

byteArrayToBS :: ByteArray bs => bs -> ByteString
byteArrayToBS bs = byteArrayCopyAndFreeze bs (\_ -> return ())

byteArrayFromBS :: ByteArray bs => ByteString -> bs
byteArrayFromBS bs = byteArrayCopyAndFreeze bs (\_ -> return ())

byteArrayToW64BE :: ByteArrayAccess bs => bs -> Int -> Word64
byteArrayToW64BE bs ofs = unsafeDoIO $ withByteArray bs $ \p -> fromBE64 <$> peek (p `plusPtr` ofs)
