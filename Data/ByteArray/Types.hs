-- |
-- Module      : Data.ByteArray.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE CPP #-}
module Data.ByteArray.Types
    ( ByteArrayAccess(..)
    , ByteArray(..)
    ) where

import           Foreign.Ptr

#ifdef WITH_BYTESTRING_SUPPORT
import qualified Data.ByteString as B (length)
import qualified Data.ByteString.Internal as B
import           Foreign.ForeignPtr (withForeignPtr)
#endif

class ByteArrayAccess ba where
    length        :: ba -> Int
    withByteArray :: ba -> (Ptr p -> IO a) -> IO a

class ByteArrayAccess ba => ByteArray ba where
    allocRet  :: Int -> (Ptr p -> IO a) -> IO (a, ba)

#ifdef WITH_BYTESTRING_SUPPORT
instance ByteArrayAccess B.ByteString where
    length = B.length
    withByteArray b f = withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
      where (fptr, off, _) = B.toForeignPtr b

instance ByteArray B.ByteString where
    allocRet sz f = do
        fptr <- B.mallocByteString sz
        r    <- withForeignPtr fptr (f . castPtr)
        return (r, B.PS fptr 0 sz)
#endif

