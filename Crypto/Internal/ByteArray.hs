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
    (
      ByteArray(..)
    , ByteArrayAccess(..)
    -- * Inhabitants
    , Bytes
    , SecureBytes
    -- * methods
    , byteArrayAlloc
    , byteArrayAllocAndFreeze
    , empty
    , byteArrayZero
    , byteArrayCopy
    , byteArrayCopyRet
    , byteArrayCopyAndFreeze
    , byteArraySplit
    , byteArrayXor
    , byteArrayEq
    , byteArrayIndex
    , byteArrayConstEq
    , byteArrayConcat
    , byteArrayToBS
    , byteArrayFromBS
    , byteArrayToW64BE
    , byteArrayToW64LE
    , byteArrayMapAsWord64
    , byteArrayMapAsWord128
    ) where

import Data.SecureMem
import Crypto.Internal.Memory
import Crypto.Internal.Compat
import Crypto.Internal.Endian
import Crypto.Internal.Bytes (bufXor, bufCopy, bufSet)
import Crypto.Internal.Words
import Crypto.Internal.Imports hiding (empty)
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
    byteArrayAllocRet  :: Int -> (Ptr p -> IO a) -> IO (a, ba)

byteArrayAlloc :: ByteArray ba => Int -> (Ptr p -> IO ()) -> IO ba
byteArrayAlloc n f = snd `fmap` byteArrayAllocRet n f

instance ByteArrayAccess Bytes where
    byteArrayLength = bytesLength
    withByteArray   = withBytes
instance ByteArray Bytes where
    byteArrayAllocRet = bytesAllocRet

instance ByteArrayAccess ByteString where
    byteArrayLength = B.length
    withByteArray b f = withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
      where (fptr, off, _) = B.toForeignPtr b
instance ByteArray ByteString where
    byteArrayAllocRet sz f = do
        fptr <- B.mallocByteString sz
        r    <- withForeignPtr fptr (f . castPtr)
        return (r, B.PS fptr 0 sz)

instance ByteArrayAccess SecureMem where
    byteArrayLength = secureMemGetSize
    withByteArray b f = withSecureMemPtr b (f . castPtr)
instance ByteArray SecureMem where
    byteArrayAllocRet sz f = do
        out <- allocateSecureMem sz
        r   <- withSecureMemPtr out (f . castPtr)
        return (r, out)

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

byteArrayIndex :: ByteArrayAccess a => a -> Int -> Word8
byteArrayIndex b i = unsafeDoIO $ withByteArray b $ \p -> peek (p `plusPtr` i)

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

byteArrayCopy :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO ()) -> IO bs2
byteArrayCopy bs f =
    byteArrayAlloc (byteArrayLength bs) $ \d -> do
        withByteArray bs $ \s -> bufCopy d s (byteArrayLength bs)
        f (castPtr d)

byteArrayCopyRet :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO a) -> IO (a, bs2)
byteArrayCopyRet bs f =
    byteArrayAllocRet (byteArrayLength bs) $ \d -> do
        withByteArray bs $ \s -> bufCopy d s (byteArrayLength bs)
        f (castPtr d)

byteArrayCopyAndFreeze :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO ()) -> bs2
byteArrayCopyAndFreeze bs f =
    byteArrayAllocAndFreeze (byteArrayLength bs) $ \d -> do
        withByteArray bs $ \s -> bufCopy d s (byteArrayLength bs)
        f (castPtr d)

byteArrayZero :: ByteArray ba => Int -> ba
byteArrayZero n = byteArrayAllocAndFreeze n $ \ptr -> bufSet ptr 0 n

byteArrayEq :: (ByteArrayAccess bs1, ByteArrayAccess bs2) => bs1 -> bs2 -> Bool
byteArrayEq b1 b2
    | l1 /= l2  = False
    | otherwise = unsafeDoIO $
        withByteArray b1 $ \p1 ->
        withByteArray b2 $ \p2 ->
            loop l1 p1 p2
  where
    l1 = byteArrayLength b1
    l2 = byteArrayLength b2
    loop :: Int -> Ptr Word8 -> Ptr Word8 -> IO Bool
    loop 0 _  _  = return True
    loop i p1 p2 = do
        e <- (==) <$> peek p1 <*> peek p2
        if e then loop (i-1) (p1 `plusPtr` 1) (p2 `plusPtr` 1) else return False

-- | A constant time equality test for 2 ByteArrayAccess values.
--
-- If values are of 2 different sizes, the function will abort early
-- without comparing any bytes.
--
-- compared to == , this function will go over all the bytes
-- present before yielding a result even when knowing the
-- overall result early in the processing.
byteArrayConstEq :: (ByteArrayAccess bs1, ByteArrayAccess bs2) => bs1 -> bs2 -> Bool
byteArrayConstEq b1 b2
    | l1 /= l2  = False
    | otherwise = unsafeDoIO $
        withByteArray b1 $ \p1 ->
        withByteArray b2 $ \p2 ->
            loop l1 True p1 p2
  where
    l1 = byteArrayLength b1
    l2 = byteArrayLength b2
    loop :: Int -> Bool -> Ptr Word8 -> Ptr Word8 -> IO Bool
    loop 0 !ret _  _  = return ret
    loop i !ret p1 p2 = do
        e <- (==) <$> peek p1 <*> peek p2
        loop (i-1) (ret &&! e) (p1 `plusPtr` 1) (p2 `plusPtr` 1)

    -- Bool == Bool
    (&&!) :: Bool -> Bool -> Bool
    True  &&! True  = True
    True  &&! False = False
    False &&! True  = False
    False &&! False = False

byteArrayToBS :: ByteArray bs => bs -> ByteString
byteArrayToBS bs = byteArrayCopyAndFreeze bs (\_ -> return ())

byteArrayFromBS :: ByteArray bs => ByteString -> bs
byteArrayFromBS bs = byteArrayCopyAndFreeze bs (\_ -> return ())

byteArrayToW64BE :: ByteArrayAccess bs => bs -> Int -> Word64
byteArrayToW64BE bs ofs = unsafeDoIO $ withByteArray bs $ \p -> fromBE64 <$> peek (p `plusPtr` ofs)

byteArrayToW64LE :: ByteArrayAccess bs => bs -> Int -> Word64
byteArrayToW64LE bs ofs = unsafeDoIO $ withByteArray bs $ \p -> fromLE64 <$> peek (p `plusPtr` ofs)

byteArrayMapAsWord128 :: ByteArray bs => (Word128 -> Word128) -> bs -> bs
byteArrayMapAsWord128 f bs =
    byteArrayAllocAndFreeze len $ \dst ->
    withByteArray bs            $ \src ->
        loop (len `div` 16) dst src
  where
        len        = byteArrayLength bs
        loop 0 _ _ = return ()
        loop i d s = do
            w1 <- peek s
            w2 <- peek (s `plusPtr` 8)
            let (Word128 r1 r2) = f (Word128 (fromBE64 w1) (fromBE64 w2))
            poke d               (toBE64 r1)
            poke (d `plusPtr` 8) (toBE64 r2)
            loop (i-1) (d `plusPtr` 16) (s `plusPtr` 16)

byteArrayMapAsWord64 :: ByteArray bs => (Word64 -> Word64) -> bs -> bs
byteArrayMapAsWord64 f bs =
    byteArrayAllocAndFreeze len $ \dst ->
    withByteArray bs            $ \src ->
        loop (len `div` 8) dst src
  where
        len        = byteArrayLength bs
        loop 0 _ _ = return ()
        loop i d s = do
            w <- peek s
            let r = f (fromBE64 w)
            poke d (toBE64 r)
            loop (i-1) (d `plusPtr` 8) (s `plusPtr` 8)
