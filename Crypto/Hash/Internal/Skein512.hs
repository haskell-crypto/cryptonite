-- |
-- Module      : Crypto.Hash.Internal.Skein512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing Skein512 bindings
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.Internal.Skein512
    ( Ctx(..)
    -- * Internal values
    , sizeCtx
    -- * Internal IO hash functions
    , internalInit
    , internalInitAt
    , internalUpdate
    , internalUpdateUnsafe
    , internalFinalize
    -- * Context copy and creation
    , withCtxCopy
    , withCtxNewThrow
    , withCtxThrow
    ) where

import           Foreign.Ptr
import           Foreign.Storable (peek)
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Data.Word
import           Crypto.Internal.Memory

newtype Ctx = Ctx Bytes

{- return the number of bytes of output for the digest -}
peekHashlen :: Ptr Ctx -> IO Int
peekHashlen ptr = peek iptr >>= \v -> return $! fromIntegral v
    where iptr :: Ptr Word32
          iptr = castPtr ptr

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 160

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx b) f = Ctx `fmap` bytesCopyAndModify b f

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx b) f = bytesCopyTemporary b f

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = bytesTemporary 160 f

foreign import ccall unsafe "cryptonite_skein512.h cryptonite_skein512_init"
    c_skein512_init :: Ptr Ctx -> Word32 -> IO ()

foreign import ccall "cryptonite_skein512.h cryptonite_skein512_update"
    c_skein512_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_skein512.h cryptonite_skein512_update"
    c_skein512_update_unsafe :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_skein512.h cryptonite_skein512_finalize"
    c_skein512_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

internalInitAt :: Int -> Ptr Ctx -> IO ()
internalInitAt hashlen ptr = c_skein512_init ptr (fromIntegral hashlen)

-- | init a context
internalInit :: Int -> IO Ctx
internalInit hashlen = Ctx `fmap` bytesAlloc 160 (internalInitAt hashlen)

-- | Update a context in place
internalUpdate :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdate ptr d =
    B.withByteArray d $ \cs -> c_skein512_update ptr cs (fromIntegral $ B.length d)

-- | Update a context in place using an unsafe foreign function call.
--
-- It is faster than `internalUpdate`, but will block the haskell runtime.
-- This shouldn't be used if the input data is large.
internalUpdateUnsafe :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdateUnsafe ptr d =
    B.withByteArray d $ \cs -> c_skein512_update_unsafe ptr cs (fromIntegral $ B.length d)

-- | Finalize a context in place
internalFinalize :: ByteArray output => Ptr Ctx -> IO output
internalFinalize ptr =
    peekHashlen ptr >>= \digestSize -> B.alloc digestSize (c_skein512_finalize ptr)
