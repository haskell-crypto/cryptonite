-- |
-- Module      : Data.Memory.ByteArray.Bytes
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
module Data.Memory.ByteArray.Bytes
    ( Bytes
    ) where

import           GHC.Types
import           GHC.Prim
import           GHC.Ptr
import           Data.Memory.Internal.CompatPrim
import           Data.Memory.Internal.Compat      (unsafeDoIO)
import           Data.Memory.ByteArray.Types
import           Data.Memory.Encoding.Base16      (showHexadecimal)

data Bytes = Bytes (MutableByteArray# RealWorld)

instance Show Bytes where
    show = bytesShowHex
instance Eq Bytes where
    (==) = bytesEq

instance ByteArrayAccess Bytes where
    length        = bytesLength
    withByteArray = withBytes
instance ByteArray Bytes where
    allocRet = bytesAllocRet

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

{-
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
-}

bytesAllocRet :: Int -> (Ptr p -> IO a) -> IO (a, Bytes)
bytesAllocRet sz f = do
    ba <- newBytes sz
    r <- withPtr ba f
    return (r, ba)

bytesLength :: Bytes -> Int
bytesLength = sizeofBytes

withBytes :: Bytes -> (Ptr p -> IO a) -> IO a
withBytes = withPtr

bytesEq :: Bytes -> Bytes -> Bool
bytesEq b1@(Bytes m1) b2@(Bytes m2)
    | l1 /= l2  = False
    | otherwise = unsafeDoIO $ IO $ \s -> loop 0# s
  where
    !l1@(I# len) = bytesLength b1
    !l2          = bytesLength b2

    loop i s
        | booleanPrim (i ==# len) = (# s, True #)
        | otherwise               =
            case readWord8Array# m1 i s of
                (# s', e1 #) -> case readWord8Array# m2 i s' of
                    (# s'', e2 #) ->
                        if booleanPrim (eqWord# e1 e2)
                            then loop (i +# 1#) s''
                            else (# s', False #)

{-
bytesIndex :: Bytes -> Int -> Word8
bytesIndex (Bytes m) (I# i) = unsafeDoIO $ IO $ \s ->
    case readWord8Array# m i s of
        (# s', e #) -> (# s', W8# e #)
{-# NOINLINE bytesIndex #-}
-}

bytesShowHex :: Bytes -> String
bytesShowHex b = showHexadecimal (withPtr b) (bytesLength b)
{-# NOINLINE bytesShowHex #-}
