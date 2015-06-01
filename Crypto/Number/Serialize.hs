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
import           Crypto.Number.Compat
import           Crypto.Internal.Compat (unsafeDoIO)
import qualified Crypto.Number.Serialize.Internal as Internal
import qualified Crypto.Internal.ByteArray as B

-- | os2ip converts a byte string into a positive integer
os2ip :: B.ByteArrayAccess ba => ba -> Integer
os2ip bs = unsafeDoIO $ B.withByteArray bs $ \src -> Internal.os2ip src (B.length bs)

-- | i2osp converts a positive integer into a byte string
--
-- first byte is MSB (most significant byte), last byte is the LSB (least significant byte)
i2osp :: B.ByteArray ba => Integer -> ba
i2osp 0 = B.allocAndFreeze 1 $ \p -> pokeByteOff p 0 (0 :: Word8)
i2osp m = B.allocAndFreeze sz (\p -> Internal.i2osp m p sz >> return ())
  where
    !sz = lengthBytes m

-- | just like i2osp, but take an extra parameter for size.
-- if the number is too big to fit in @len bytes, nothing is returned
-- otherwise the number is padded with 0 to fit the @len required.
i2ospOf :: B.ByteArray ba => Int -> Integer -> Maybe ba
i2ospOf len m
    | len <= 0  = Nothing
    | m < 0     = Nothing
    | otherwise = Just $ B.unsafeCreate len $ \p -> Internal.i2ospOf m p len >> return ()

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
