-- |
-- Module      : Data.Memory.PtrMethods
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- methods to manipulate raw memory representation
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Data.Memory.PtrMethods
    ( memCreateTemporary
    , memXor
    , memXorWith
    , memCopy
    , memSet
    , memEqual
    , memConstEqual
    , memCompare
    ) where

import           Data.Memory.Internal.Imports
import           Foreign.Ptr              (Ptr, plusPtr)
import           Foreign.Storable         (peek, poke, pokeByteOff, peekByteOff)
import           Foreign.C.Types
import           Foreign.Marshal.Alloc    (allocaBytesAligned)
import           Data.Bits                (xor)

-- | Create a new temporary buffer
memCreateTemporary :: Int -> (Ptr Word8 -> IO a) -> IO a
memCreateTemporary size f = allocaBytesAligned size 8 f

-- | xor bytes from source1 and source2 to destination
-- 
-- d = s1 xor s2
--
-- s1, nor s2 are modified unless d point to s1 or s2
memXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
memXor _ _  _  0 = return ()
memXor d s1 s2 n = do
    (xor <$> peek s1 <*> peek s2) >>= poke d
    memXor (d `plusPtr` 1) (s1 `plusPtr` 1) (s2 `plusPtr` 1) (n-1)

-- | xor bytes from source with a specific value to destination
--
-- d = replicate (sizeof s) v `xor` s
memXorWith :: Ptr Word8 -> Word8 -> Ptr Word8 -> Int -> IO ()
memXorWith d v s n = loop 0
  where
    loop i
        | i == n    = return ()
        | otherwise = do
            (xor v <$> peekByteOff s i) >>= pokeByteOff d i
            loop (i+1)

-- | Copy a set number of bytes from @src to @dst
memCopy :: Ptr Word8 -> Ptr Word8 -> Int -> IO ()
memCopy dst src n = c_memcpy dst src (fromIntegral n)

-- | Set @n number of bytes to the same value @v
memSet :: Ptr Word8 -> Word8 -> Int -> IO ()
memSet start v n = c_memset start (fromIntegral v) (fromIntegral n) >>= \_ -> return ()

memEqual :: Ptr Word8 -> Ptr Word8 -> Int -> IO Bool
memEqual p1 p2 n = loop 0
  where
    loop i
        | i == n    = return True
        | otherwise = do
            e <- (==) <$> peekByteOff p1 i <*> (peekByteOff p2 i :: IO Word8)
            if e then loop (i+1) else return False

memCompare :: Ptr Word8 -> Ptr Word8 -> Int -> IO Ordering
memCompare p1 p2 n = loop 0
  where
    loop i
        | i == n    = return EQ
        | otherwise = do
            e <- compare <$> peekByteOff p1 i <*> (peekByteOff p2 i :: IO Word8)
            if e == EQ then loop (i+1) else return e

-- | A constant time equality test for 2 Memory buffers
--
-- compared to normal equality function, this function will go
-- over all the bytes present before yielding a result even when
-- knowing the overall result early in the processing.
memConstEqual :: Ptr Word8 -> Ptr Word8 -> Int -> IO Bool
memConstEqual p1 p2 n = loop 0 True
  where
    loop i !ret
        | i == n    = return ret
        | otherwise = do
            e <- (==) <$> peek p1 <*> peek p2
            loop (i+1) (ret &&! e)

    -- Bool == Bool
    (&&!) :: Bool -> Bool -> Bool
    True  &&! True  = True
    True  &&! False = False
    False &&! True  = False
    False &&! False = False

foreign import ccall unsafe "memset"
    c_memset :: Ptr Word8 -> Word8 -> CSize -> IO ()

foreign import ccall unsafe "memcpy"
    c_memcpy :: Ptr Word8 -> Ptr Word8 -> CSize -> IO ()
