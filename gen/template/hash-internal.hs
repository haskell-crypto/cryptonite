-- |
-- Module      : Crypto.Hash.Internal.%%MODULENAME%%
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing %%MODULENAME%% bindings
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.Internal.%%MODULENAME%%
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
digestSize = %%DIGESTSIZE%%

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = %%SIZECTX%%

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx b) f = Ctx `fmap` bytesCopyAndModify b f

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx b) f = bytesCopyTemporary b f

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = bytesTemporary %%SIZECTX%% f

foreign import ccall unsafe "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_init"
    c_%%HASHNAME%%_init :: Ptr Ctx -> IO ()

foreign import ccall "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_update"
    c_%%HASHNAME%%_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_update"
    c_%%HASHNAME%%_update_unsafe :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_finalize"
    c_%%HASHNAME%%_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

internalInitAt :: Ptr Ctx -> IO ()
internalInitAt = c_%%HASHNAME%%_init

-- | init a context
internalInit :: IO Ctx
internalInit = Ctx `fmap` bytesAlloc %%SIZECTX%% internalInitAt

-- | Update a context in place
internalUpdate :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdate ptr d =
    B.withByteArray d $ \cs -> c_%%HASHNAME%%_update ptr cs (fromIntegral $ B.length d)

-- | Update a context in place using an unsafe foreign function call.
--
-- It is faster than `internalUpdate`, but will block the haskell runtime.
-- This shouldn't be used if the input data is large.
internalUpdateUnsafe :: ByteArrayAccess ba => Ptr Ctx -> ba -> IO ()
internalUpdateUnsafe ptr d =
    B.withByteArray d $ \cs -> c_%%HASHNAME%%_update_unsafe ptr cs (fromIntegral $ B.length d)

-- | Finalize a context in place
internalFinalize :: ByteArray output => Ptr Ctx -> IO output
internalFinalize ptr = B.alloc digestSize (c_%%HASHNAME%%_finalize ptr)
