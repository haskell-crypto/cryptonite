-- |
-- Module      : Crypto.Hash.Skein256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the pure functions to work with the
-- Skein256 cryptographic hash.
--
-- it is recommended to import this module qualified.
--
module Crypto.Hash.Skein256
    ( Ctx(..)

    -- * Incremental hashing Functions
    , init
    , update
    , updates
    , finalize

    -- * Single Pass hashing
    , hash
    , hashlazy
    ) where

import           Prelude hiding (init)
import qualified Data.ByteString.Lazy as L
import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import           Crypto.Internal.Compat (unsafeDoIO)
import           Crypto.Hash.Internal.Skein256

{-# NOINLINE init #-}
-- | init a context where
init :: Int -- ^ algorithm hash size in bits
     -> Ctx
init hashlen = unsafeDoIO (internalInit hashlen)

{-# NOINLINE update #-}
-- | update a context with a bytestring returning the new updated context
update :: ByteArrayAccess ba
       => Ctx  -- ^ the context to update
       -> ba   -- ^ the data to update with
       -> Ctx  -- ^ the updated context
update ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> internalUpdate ptr d

{-# NOINLINE updates #-}
-- | updates a context with multiples bytestring returning the new updated context
updates :: ByteArrayAccess ba
        => Ctx  -- ^ the context to update
        -> [ba] -- ^ a list of data bytestring to update with
        -> Ctx  -- ^ the updated context
updates ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (internalUpdate ptr) d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: ByteArray digest => Ctx -> digest
finalize ctx = unsafeDoIO $ withCtxThrow ctx internalFinalize

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: (ByteArray digest, ByteArrayAccess ba)
     => Int    -- ^ algorithm hash size in bits
     -> ba     -- ^ the data to hash
     -> digest -- ^ the digest output
hash hashlen d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt hashlen ptr >> internalUpdate ptr d >> internalFinalize ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: ByteArray digest
         => Int          -- ^ algorithm hash size in bits
         -> L.ByteString -- ^ the data to hash as a lazy bytestring
         -> digest       -- ^ the digest output
hashlazy hashlen l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt hashlen ptr >> mapM_ (internalUpdate ptr) (L.toChunks l) >> internalFinalize ptr
