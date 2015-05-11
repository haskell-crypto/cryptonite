-- |
-- Module      : Crypto.Number.Serialize
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- fast serialization primitives for integer
{-# LANGUAGE BangPatterns #-}
module Crypto.Number.Serialize
    ( i2osp
    , os2ip
    , i2ospOf
    , i2ospOf_
    , lengthBytes
    ) where

import           Data.Bits
import           Data.Word
import           Foreign.Storable
import           Foreign.Ptr
import           Crypto.Number.Compat
import           Crypto.Internal.Compat (unsafeDoIO)
import qualified Crypto.Internal.ByteArray as B
import           Data.Memory.PtrMethods

divMod256 :: Integer -> (Integer, Word8)
divMod256 n = (n `shiftR` 8, fromIntegral n)

-- | os2ip converts a byte string into a positive integer
os2ip :: B.ByteArrayAccess ba => ba -> Integer
os2ip bs = unsafeDoIO $ B.withByteArray bs (loop 0 0)
  where
        len = B.length bs

        loop :: Integer -> Int -> Ptr Word8 -> IO Integer
        loop !acc i p
            | i == len  = return acc
            | otherwise = do
                w <- peekByteOff p i :: IO Word8
                loop ((acc `shiftL` 8) .|. fromIntegral w) (i+1) p

-- | i2osp converts a positive integer into a byte string
--
-- first byte is MSB (most significant byte), last byte is the LSB (least significant byte)
i2osp :: B.ByteArray ba => Integer -> ba
i2osp 0 = B.allocAndFreeze 1 $ \p -> pokeByteOff p 0 (0 :: Word8)
i2osp m = B.allocAndFreeze sz (\p -> fillPtr p >> return ())
  where
        !sz = lengthBytes m

        fillPtr p = gmpExportInteger m p `onGmpUnsupported` export p (sz-1) m
        export p ofs i
            | ofs == 0  = pokeByteOff p ofs (fromIntegral i :: Word8)
            | otherwise = do
                let (i', b) = divMod256 i
                pokeByteOff p ofs b
                export p (ofs-1) i'

-- | just like i2osp, but take an extra parameter for size.
-- if the number is too big to fit in @len bytes, nothing is returned
-- otherwise the number is padded with 0 to fit the @len required.
i2ospOf :: B.ByteArray ba => Int -> Integer -> Maybe ba
i2ospOf 0   _ = error "cannot create integer serialization in 0 bytes"
i2ospOf len 0 = Just $ B.allocAndFreeze len $ \p -> memSet p 0 len
i2ospOf len m
    | sz > len  = Nothing
    | otherwise = Just $ B.allocAndFreeze len $ \p -> memSet p 0 len >> fillPtr (p `plusPtr` (len - sz))
  where
        !sz = lengthBytes m

        fillPtr p = gmpExportInteger m p `onGmpUnsupported` export p (sz-1) m
        export p ofs i
            | ofs == 0  = pokeByteOff p ofs (fromIntegral i :: Word8)
            | otherwise = do
                let (i', b) = divMod256 i
                pokeByteOff p ofs b
                export p (ofs-1) i'

--
-- | just like i2ospOf except that it doesn't expect a failure: i.e.
-- an integer larger than the number of output bytes requested
--
-- for example if you just took a modulo of the number that represent
-- the size (example the RSA modulo n).
i2ospOf_ :: B.ByteArray ba => Int -> Integer -> ba
i2ospOf_ len = maybe (error "i2ospOf_: integer is larger than expected") id . i2ospOf len

-- | returns the number of bytes to store an integer with i2osp
--
-- with integer-simple, this function is really slow.
lengthBytes :: Integer -> Int
lengthBytes n = gmpSizeInBytes n `onGmpUnsupported` nbBytes n
  where
    nbBytes !v
        | v < 256   = 1
        | otherwise = 1 + nbBytes (v `shiftR` 8)
