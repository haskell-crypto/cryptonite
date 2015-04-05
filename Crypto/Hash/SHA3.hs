-- |
-- Module      : Crypto.Hash.SHA3
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the pure functions to work with the
-- SHA3 cryptographic hash.
--
-- it is recommended to import this module qualified.
--
module Crypto.Hash.SHA3
    ( Ctx(..)

    -- * Incremental hashing Functions
    , init     -- :: Int -> Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: Int -> ByteString -> ByteString
    , hashlazy -- :: Int -> ByteString -> ByteString
    ) where

import Prelude hiding (init)
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Crypto.Internal.Compat (unsafeDoIO)
import Crypto.Hash.Internal.SHA3

{-# NOINLINE init #-}
-- | init a context where
init :: Int -- ^ algorithm hash size in bits
     -> Ctx
init hashlen = unsafeDoIO (internalInit hashlen)

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
hash :: Int        -- ^ algorithm hash size in bits
     -> ByteString -- ^ the data to hash
     -> ByteString -- ^ the digest output
hash hashlen d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt hashlen ptr >> internalUpdate ptr d >> internalFinalize ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int          -- ^ algorithm hash size in bits
         -> L.ByteString -- ^ the data to hash as a lazy bytestring
         -> ByteString   -- ^ the digest output
hashlazy hashlen l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    internalInitAt hashlen ptr >> mapM_ (internalUpdate ptr) (L.toChunks l) >> internalFinalize ptr
