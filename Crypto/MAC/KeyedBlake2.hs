-- |
-- Module      : Crypto.MAC.KeyedBlake2
-- License     : BSD-style
-- Maintainer  : Matthias Valvekens <dev@mvalvekens.be>
-- Stability   : experimental
-- Portability : unknown
--
-- Expose a MAC interface to the keyed Blake2 algorithms
-- defined in RFC 7693.
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.MAC.KeyedBlake2
    ( HashBlake2
    , KeyedBlake2(..)
    , keyedBlake2
    , keyedBlake2Lazy
    -- * Incremental
    , Context
    , initialize
    , update
    , updates
    , finalize
    ) where

import qualified Crypto.Hash as H
import qualified Crypto.Hash.Types as H
import           Crypto.Hash.Blake2
import           Crypto.Internal.DeepSeq (NFData)
import qualified Data.ByteArray as B
import           Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteString.Lazy as L

import           Foreign.Ptr (Ptr)


-- Keyed Blake2b

-- | Represent a Blake2b MAC that is a phantom type with the hash used to produce the
-- MAC.
--
-- The Eq instance is constant time.  No Show instance is provided, to avoid
-- printing by mistake.
newtype KeyedBlake2 a = KeyedBlake2 { keyedBlake2GetDigest :: H.Digest a }
    deriving (ByteArrayAccess,NFData)

instance Eq (KeyedBlake2 a) where
    KeyedBlake2 x == KeyedBlake2 y = B.constEq x y

-- | Represent an ongoing Blake2 state, that can be appended with 'update' and
-- finalized to a 'KeyedBlake2' with 'finalize'.
newtype Context a = Context (H.Context a)

-- | Initialize a new incremental keyed Blake2 context with the supplied key.
initialize :: forall a key . (HashBlake2 a, ByteArrayAccess key)
           => key -> Context a
initialize k = Context $ H.Context $ B.allocAndFreeze ctxSz performInit
    where ctxSz = H.hashInternalContextSize (undefined :: a)
          digestSz = H.hashDigestSize (undefined :: a)
          -- cap the number of key bytes at digestSz,
          -- since that's the maximal key size
          keyByteLen = min (B.length k) digestSz
          performInit :: Ptr (H.Context a) -> IO ()
          performInit ptr = B.withByteArray k
            $ \keyPtr -> blake2InternalKeyedInit ptr keyPtr (fromIntegral keyByteLen)

-- | Incrementally update a keyed Blake2 context.
update :: (HashBlake2 a, ByteArrayAccess ba) => Context a -> ba -> Context a
update (Context ctx) = Context . H.hashUpdate ctx

-- | Incrementally update a keyed Blake2 context with multiple inputs.
updates :: (HashBlake2 a, ByteArrayAccess ba) => Context a -> [ba] -> Context a
updates (Context ctx) = Context . H.hashUpdates ctx

-- | Finalize a keyed Blake2 context and return the computed MAC.
finalize :: HashBlake2 a => Context a -> KeyedBlake2 a
finalize (Context ctx) = KeyedBlake2 $ H.hashFinalize ctx

-- | Compute a Blake2 MAC using the supplied key.
keyedBlake2 :: (HashBlake2 a, ByteArrayAccess key, ByteArrayAccess ba)
            => key -> ba -> KeyedBlake2 a
keyedBlake2 key msg = finalize $ update (initialize key) msg

-- | Compute a Blake2 MAC using the supplied key, for a lazy input.
keyedBlake2Lazy :: (HashBlake2 a, ByteArrayAccess key)
            => key -> L.ByteString -> KeyedBlake2 a
keyedBlake2Lazy key msg = finalize $ updates (initialize key) (L.toChunks msg)
