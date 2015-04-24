-- |
-- Module      : Crypto.Hash.Internal.SHA384
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA384 bindings
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.Internal.SHA384
    ( Ctx(..)
    -- * Internal values
    , digestSize
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
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Data.Word
import           Crypto.Internal.Memory

newtype Ctx = Ctx Bytes

{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 48

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 256

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx b) f = Ctx `fmap` bytesCopyAndModify b f

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx b) f = bytesCopyTemporary b f

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = bytesTemporary 256 f

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha384_init"
    c_sha384_init :: Ptr Ctx -> IO ()

foreign import ccall "cryptonite_sha512.h cryptonite_sha384_update"
    c_sha384_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha384_update"
    c_sha384_update_unsafe :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha384_finalize"
    c_sha384_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

internalInitAt :: Ptr Ctx -> IO ()
internalInitAt = c_sha384_init

-- | init a context
internalInit :: IO Ctx
internalInit = Ctx `fmap` bytesAlloc 256 internalInitAt

-- | Update a context in place
internalUpdate :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdate ptr d =
    B.withByteArray d $ \cs -> c_sha384_update ptr cs (fromIntegral $ B.length d)

-- | Update a context in place using an unsafe foreign function call.
--
-- It is faster than `internalUpdate`, but will block the haskell runtime.
-- This shouldn't be used if the input data is large.
internalUpdateUnsafe :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdateUnsafe ptr d =
    B.withByteArray d $ \cs -> c_sha384_update_unsafe ptr cs (fromIntegral $ B.length d)

-- | Finalize a context in place
internalFinalize :: ByteArray output => Ptr Ctx -> IO output
internalFinalize ptr = B.alloc digestSize (c_sha384_finalize ptr)
