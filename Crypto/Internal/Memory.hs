-- |
-- Module      : Crypto.Internal.Memory
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
module Crypto.Internal.Memory
    ( Bytes
    , bytesCopyAndModify
    , bytesTemporary
    , bytesCopyTemporary
    , bytesAlloc
    , bytesLength
    , withBytes
    ) where

import Data.Word
import GHC.Types
import GHC.Prim
import GHC.Ptr
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable      (pokeElemOff)
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils (copyBytes)

data Bytes = Bytes (MutableByteArray# RealWorld)

------------------------------------------------------------------------
newBytes :: Int -> IO Bytes
newBytes (I# sz) = IO $ \s ->
    case newAlignedPinnedByteArray# sz 8# s of
        (# s', mbarr #) -> (# s', Bytes mbarr #)

touchBytes :: Bytes -> IO ()
touchBytes (Bytes mba) = IO $ \s -> case touch# mba s of s' -> (# s', () #)

sizeofBytes :: Bytes -> Int
sizeofBytes (Bytes mba) = I# (sizeofMutableByteArray# mba)

withPtr :: Bytes -> (Ptr p -> IO a) -> IO a
withPtr b@(Bytes mba) f = do
    a <- f (Ptr (byteArrayContents# (unsafeCoerce# mba)))
    touchBytes b
    return a
------------------------------------------------------------------------

bytesCopyAndModify :: Bytes -> (Ptr a -> IO ()) -> IO Bytes
bytesCopyAndModify src f = do
    dst <- newBytes sz
    withPtr dst $ \d -> do
        withPtr src $ \s -> copyBytes (castPtr d) s sz
        f d
    return dst
  where sz = sizeofBytes src

bytesTemporary :: Int -> (Ptr p -> IO a) -> IO a
bytesTemporary sz f = newBytes sz >>= \ba -> withPtr ba f

bytesCopyTemporary :: Bytes -> (Ptr p -> IO a) -> IO a
bytesCopyTemporary src f = do
    dst <- newBytes (sizeofBytes src)
    withPtr dst $ \d -> do
        withPtr src $ \s -> copyBytes (castPtr d) s (sizeofBytes src)
        f d

bytesAlloc :: Int -> (Ptr p -> IO ()) -> IO Bytes
bytesAlloc sz f = do
    ba <- newBytes sz
    withPtr ba f
    return ba

bytesLength :: Bytes -> Int
bytesLength = sizeofBytes

withBytes :: Bytes -> (Ptr p -> IO a) -> IO a
withBytes = withPtr
