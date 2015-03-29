-- |
-- Module      : Crypto.Internal.Bytes
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- internal helpers function to manipulate sequence of bytes
-- like ByteString and buffer.
--
module Crypto.Internal.Bytes
    ( withByteStringPtr
    , tempBufCreate
    , bufXor
    ) where

import Control.Applicative      ((<$>), (<*>))
import Foreign.Ptr              (Ptr, plusPtr)
import Foreign.ForeignPtr       (withForeignPtr)
import Foreign.Storable         (peek, poke)
import Foreign.Marshal.Alloc    (allocaBytesAligned)
import Data.ByteString          (ByteString)
import Data.Bits                (xor)
import Data.Word                (Word8)
import Data.ByteString.Internal (toForeignPtr)

withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
  where (fptr, off, _) = toForeignPtr b

-- | Create a new temporary buffer
tempBufCreate :: Int -> (Ptr Word8 -> IO a) -> IO a
tempBufCreate size f = allocaBytesAligned size 8 f

-- | xor bytes from source1 and source2 to destination
-- 
-- d = s1 xor s2
--
-- s1, nor s2 are modified unless d point to s1 or s2
bufXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
bufXor _ _  _  0 = return ()
bufXor d s1 s2 n = do
    (xor <$> peek s1 <*> peek s2) >>= poke d
    bufXor (d `plusPtr` 1) (s1 `plusPtr` 1) (s2 `plusPtr` 1) (n-1)
