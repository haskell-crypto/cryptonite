-- |
-- Module      : Crypto.Number.Serialize.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- fast serialization primitives for integer using raw pointers
{-# LANGUAGE BangPatterns #-}
module Crypto.Number.Serialize.Internal
    ( i2osp
    , i2ospOf
    , os2ip
    ) where

import           Crypto.Number.Compat
import           Crypto.Number.Basic
import           Data.Bits
import           Data.Memory.PtrMethods
import           Data.Word (Word8)
import           Foreign.Ptr
import           Foreign.Storable

-- | fill a pointer with the big endian binary representation of an integer
--
-- if the room available @ptrSz is less than the number of bytes needed,
-- 0 is returned. Likewise if a parameter is invalid, 0 is returned.
--
-- returns the number of bytes written
i2osp :: Integer -> Ptr Word8 -> Int -> IO Int
i2osp m ptr ptrSz
    | ptrSz <= 0 = return 0
    | m < 0      = return 0
    | m == 0     = pokeByteOff ptr 0 (0 :: Word8) >> return 1
    | ptrSz < sz = return 0
    | otherwise  = fillPtr >> return sz
  where
    !sz = numBytes m

    fillPtr = gmpExportInteger m ptr `onGmpUnsupported` export ptr (sz-1) m
    export p ofs i
        | ofs == 0  = pokeByteOff p ofs (fromIntegral i :: Word8)
        | otherwise = do
            let (i', b) = i `divMod` 256
            pokeByteOff p ofs (fromIntegral b :: Word8)
            export p (ofs-1) i'

-- | Similar to 'i2osp', except it will pad any remaining space with zero.
i2ospOf :: Integer -> Ptr Word8 -> Int -> IO Int
i2ospOf m ptr ptrSz
    | ptrSz <= 0 = return 0
    | m < 0      = return 0
    | ptrSz < sz = return 0
    | otherwise  = (if padSz > 0 then memSet ptr 0 padSz else return ()) >> fillPtr (ptr `plusPtr` padSz) >> return ptrSz
  where
    !sz    = numBytes m
    !padSz = ptrSz - sz

    fillPtr p = gmpExportInteger m p `onGmpUnsupported` export p (sz-1) m
    export p ofs i
        | ofs == 0  = pokeByteOff p ofs (fromIntegral i :: Word8)
        | otherwise = do
            let (i', b) = i `divMod` 256
            pokeByteOff p ofs (fromIntegral b :: Word8)
            export p (ofs-1) i'

-- | transform a big endian binary integer representation pointed by a pointer and a size
-- into an integer
os2ip :: Ptr Word8 -> Int -> IO Integer
os2ip ptr ptrSz
    | ptrSz <= 0 = return 0
    | otherwise  = {-gmpImportInteger ptrSz ptr `onGmpUnsupported` -} loop 0 0 ptr 
  where
    loop :: Integer -> Int -> Ptr Word8 -> IO Integer
    loop !acc i p
        | i == ptrSz = return acc
        | otherwise  = do
            w <- peekByteOff p i :: IO Word8
            loop ((acc `shiftL` 8) .|. fromIntegral w) (i+1) p
