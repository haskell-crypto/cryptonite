-- |
-- Module      : Crypto.Hash.Tiger
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the pure functions to work with the
-- Tiger cryptographic hash.
--
-- it is recommended to import this module qualified.
--
module Crypto.Hash.Tiger
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
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray)
import           Crypto.Internal.Compat (unsafeDoIO)
import           Crypto.Hash.Internal.Tiger

{-# RULES "hash" forall b. finalize (update init b) = hash b #-}
{-# RULES "hash.list1" forall b. finalize (updates init [b]) = hash b #-}
{-# RULES "hashmany" forall b. finalize (foldl update init b) = hashlazy (L.fromChunks b) #-}
{-# RULES "hashlazy" forall b. finalize (foldl update init $ L.toChunks b) = hashlazy b #-}

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = unsafeDoIO internalInit

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
     => ba
     -> digest
hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt ptr >> internalUpdate ptr d >> internalFinalize ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: ByteArray digest
         => L.ByteString
         -> digest
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt ptr >> mapM_ (internalUpdate ptr) (L.toChunks l) >> internalFinalize ptr
