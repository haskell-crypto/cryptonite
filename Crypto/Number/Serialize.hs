{-# LANGUAGE CPP #-}
#ifndef MIN_VERSION_integer_gmp
#define MIN_VERSION_integer_gmp(a,b,c) 0
#endif
#if MIN_VERSION_integer_gmp(0,5,1)
{-# LANGUAGE MagicHash, UnboxedTuples, BangPatterns #-}
#endif
-- |
-- Module      : Crypto.Number.Serialize
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- fast serialization primitives for integer
module Crypto.Number.Serialize
    ( i2osp
    , os2ip
    , i2ospOf
    , i2ospOf_
    , lengthBytes
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString as B
import Foreign.Ptr

#if MIN_VERSION_integer_gmp(0,5,1)
#if __GLASGOW_HASKELL__ >= 710
import Control.Monad (void)
#endif
import GHC.Integer.GMP.Internals
import GHC.Base
import GHC.Ptr
import System.IO.Unsafe
import Foreign.ForeignPtr
#else
import Foreign.Storable
import Data.Bits
#endif

#if !MIN_VERSION_integer_gmp(0,5,1)
{-# INLINE divMod256 #-}
divMod256 :: Integer -> (Integer, Integer)
divMod256 n = (n `shiftR` 8, n .&. 0xff)
#endif

-- | os2ip converts a byte string into a positive integer
os2ip :: ByteString -> Integer
#if MIN_VERSION_integer_gmp(0,5,1)
os2ip bs = unsafePerformIO $ withForeignPtr fptr $ \ptr ->
    let !(Ptr ad) = (ptr `plusPtr` ofs)
#if __GLASGOW_HASKELL__ >= 710
     in importIntegerFromAddr ad (int2Word# n) 1#
#else
     in IO $ \s -> importIntegerFromAddr ad (int2Word# n) 1# s
#endif
  where !(fptr, ofs, !(I# n)) = B.toForeignPtr bs
{-# NOINLINE os2ip #-}
#else
os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0
{-# INLINE os2ip #-}
#endif

-- | i2osp converts a positive integer into a byte string
i2osp :: Integer -> ByteString
#if MIN_VERSION_integer_gmp(0,5,1)
i2osp 0 = B.singleton 0
i2osp m = B.unsafeCreate (I# (word2Int# sz)) fillPtr
  where !sz = sizeInBaseInteger m 256#
#if __GLASGOW_HASKELL__ >= 710
        fillPtr (Ptr srcAddr) = void $ exportIntegerToAddr m srcAddr 1#
#else
        fillPtr (Ptr srcAddr) = IO $ \s -> case exportIntegerToAddr m srcAddr 1# s of
                                                (# s2, _ #) -> (# s2, () #)
#endif
{-# NOINLINE i2osp #-}
#else
i2osp m
    | m < 0     = error "i2osp: cannot convert a negative integer to a bytestring"
    | otherwise = B.reverse $ B.unfoldr fdivMod256 m
    where fdivMod256 0 = Nothing
          fdivMod256 n = Just (fromIntegral a,b) where (b,a) = divMod256 n
#endif


-- | just like i2osp, but take an extra parameter for size.
-- if the number is too big to fit in @len bytes, nothing is returned
-- otherwise the number is padded with 0 to fit the @len required.
--
-- FIXME: use unsafeCreate to fill the bytestring
i2ospOf :: Int -> Integer -> Maybe ByteString
#if MIN_VERSION_integer_gmp(0,5,1)
i2ospOf len m
    | sz <= len = Just $ i2ospOf_ len m
    | otherwise = Nothing
  where !sz = I# (word2Int# (sizeInBaseInteger m 256#))
#else
i2ospOf len m
    | lenbytes < len  = Just $ B.replicate (len - lenbytes) 0 `B.append` bytes
    | lenbytes == len = Just bytes
    | otherwise       = Nothing
  where lenbytes = B.length bytes
        bytes    = i2osp m
#endif

-- | just like i2ospOf except that it doesn't expect a failure: i.e.
-- an integer larger than the number of output bytes requested
--
-- for example if you just took a modulo of the number that represent
-- the size (example the RSA modulo n).
i2ospOf_ :: Int -> Integer -> ByteString
#if MIN_VERSION_integer_gmp(0,5,1)
i2ospOf_ len m = unsafePerformIO $ B.create len fillPtr
  where !sz = (sizeInBaseInteger m 256#)
        isz = I# (word2Int# sz)
        fillPtr ptr
            | len < isz  = error "cannot compute i2ospOf_ with integer larger than output bytes"
            | len == isz =
                let !(Ptr srcAddr) = ptr in
#if __GLASGOW_HASKELL__ >= 710
                void (exportIntegerToAddr m srcAddr 1#)
#else
                IO $ \s -> case exportIntegerToAddr m srcAddr 1# s of
                                (# s2, _ #) -> (# s2, () #)
#endif
            | otherwise = do
                let z = len-isz
                _ <- B.memset ptr 0 (fromIntegral len)
                let !(Ptr addr) = ptr `plusPtr` z
#if __GLASGOW_HASKELL__ >= 710
                void (exportIntegerToAddr m addr 1#)
#else
                IO $ \s -> case exportIntegerToAddr m addr 1# s of
                                (# s2, _ #) -> (# s2, () #)
#endif
{-# NOINLINE i2ospOf_ #-}
#else
i2ospOf_ len m = B.unsafeCreate len fillPtr
    where fillPtr srcPtr = loop m (srcPtr `plusPtr` (len-1))
            where loop n ptr = do
                      let (nn,a) = divMod256 n
                      poke ptr (fromIntegral a)
                      if ptr == srcPtr
                          then return ()
                          else (if nn == 0 then fillerLoop else loop nn) (ptr `plusPtr` (-1))
                  fillerLoop ptr = do
                      poke ptr 0
                      if ptr == srcPtr
                          then return ()
                          else fillerLoop (ptr `plusPtr` (-1))
{-# INLINE i2ospOf_ #-}
#endif

-- | returns the number of bytes to store an integer with i2osp
--
-- with integer-simple, this function is really slow.
lengthBytes :: Integer -> Int
#if MIN_VERSION_integer_gmp(0,5,1)
lengthBytes n = I# (word2Int# (sizeInBaseInteger n 256#))
#else
lengthBytes n
    | n < 256   = 1
    | otherwise = 1 + lengthBytes (n `shiftR` 8)
#endif
