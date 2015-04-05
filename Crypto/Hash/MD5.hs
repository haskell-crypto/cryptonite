-- |
-- Module      : Crypto.Hash.MD5
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the pure functions to work with the
-- MD5 cryptographic hash.
--
-- it is recommended to import this module qualified.
--
module Crypto.Hash.MD5
    ( Ctx(..)

    -- * Incremental hashing Functions
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: ByteString -> ByteString
    ) where

import Prelude hiding (init)
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Hash.Internal.MD5

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
update :: Ctx        -- ^ the context to update
       -> ByteString -- ^ the data to update with
       -> Ctx        -- ^ the updated context
update ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> internalUpdate ptr d

{-# NOINLINE updates #-}
-- | updates a context with multiples bytestring returning the new updated context
updates :: Ctx          -- ^ the context to update
        -> [ByteString] -- ^ a list of data bytestring to update with
        -> Ctx          -- ^ the updated context
updates ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (internalUpdate ptr) d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafeDoIO $ withCtxThrow ctx internalFinalize

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: ByteString -> ByteString
hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt ptr >> internalUpdate ptr d >> internalFinalize ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt ptr >> mapM_ (internalUpdate ptr) (L.toChunks l) >> internalFinalize ptr
