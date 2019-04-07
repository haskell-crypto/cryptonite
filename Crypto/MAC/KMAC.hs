-- |
-- Module      : Crypto.MAC.KMAC
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Provide the KMAC (Keccak Message Authentication Code) algorithm, derived from
-- the SHA-3 base algorithm Keccak and defined in NIST SP800-185.
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.MAC.KMAC
    ( HashSHAKE
    , kmac
    , KMAC(..)
    -- * Incremental
    , Context
    , initialize
    , update
    , updates
    , finalize
    ) where

import qualified Crypto.Hash as H
import           Crypto.Hash.SHAKE (HashSHAKE(..))
import           Crypto.Hash.Types (HashAlgorithm(..), Digest(..))
import qualified Crypto.Hash.Types as H
import           Crypto.Number.Serialize
import           Foreign.Ptr (Ptr)
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B


-- cSHAKE

cshakeInit :: forall a name string . (HashSHAKE a, ByteArrayAccess name, ByteArrayAccess string)
           => name -> string -> H.Context a
cshakeInit n s = H.Context $ B.allocAndFreeze c $ \(ptr :: Ptr (H.Context a)) -> do
    hashInternalInit ptr
    B.withByteArray b $ \d -> hashInternalUpdate ptr d (fromIntegral $ B.length b)
  where
    c = hashInternalContextSize (undefined :: a)
    w = hashBlockSize (undefined :: a)
    x = encodeString n `B.append` encodeString s :: B.Bytes
    b = bytepad x w

cshakeUpdate :: (HashSHAKE a, ByteArrayAccess ba)
             => H.Context a -> ba -> H.Context a
cshakeUpdate = H.hashUpdate

cshakeUpdates :: (HashSHAKE a, ByteArrayAccess ba)
              => H.Context a -> [ba] -> H.Context a
cshakeUpdates = H.hashUpdates

cshakeFinalize :: forall a . HashSHAKE a => H.Context a -> Digest a
cshakeFinalize !c =
    Digest $ B.allocAndFreeze (hashDigestSize (undefined :: a)) $ \dig -> do
        ((!_) :: B.Bytes) <- B.copy c $ \(ctx :: Ptr (H.Context a)) ->
            cshakeInternalFinalize ctx dig
        return ()


-- KMAC

-- | Represent a KMAC that is a phantom type with the hash used to produce the
-- mac.
--
-- The Eq instance is constant time.  No Show instance is provided, to avoid
-- printing by mistake.
newtype KMAC a = KMAC { kmacGetDigest :: Digest a }
    deriving ByteArrayAccess

instance Eq (KMAC a) where
    (KMAC b1) == (KMAC b2) = B.constEq b1 b2

-- | Compute a KMAC using the supplied customization string and key.
kmac :: (HashSHAKE a, ByteArrayAccess string, ByteArrayAccess key, ByteArrayAccess ba)
     => string -> key -> ba -> KMAC a
kmac str key msg = finalize $ updates (initialize str key) [msg]

-- | Represent an ongoing KMAC state, that can be appended with 'update' and
-- finalized to a 'KMAC' with 'finalize'.
newtype Context a = Context (H.Context a)

-- | Initialize a new incremental KMAC context with the supplied customization
-- string and key.
initialize :: forall a string key . (HashSHAKE a, ByteArrayAccess string, ByteArrayAccess key)
           => string -> key -> Context a
initialize str key = Context $ cshakeUpdate (cshakeInit n str) prefix
  where
    n = B.pack [75,77,65,67] :: B.Bytes  -- "KMAC"
    w = hashBlockSize (undefined :: a)
    prefix = bytepad (encodeString key) w :: B.Bytes

-- | Incrementally update a KMAC context.
update :: (HashSHAKE a, ByteArrayAccess ba) => Context a -> ba -> Context a
update (Context ctx) = Context . cshakeUpdate ctx

-- | Incrementally update a KMAC context with multiple inputs.
updates :: (HashSHAKE a, ByteArrayAccess ba) => Context a -> [ba] -> Context a
updates (Context ctx) = Context . cshakeUpdates ctx

-- | Finalize a KMAC context and return the KMAC.
finalize :: forall a . HashSHAKE a => Context a -> KMAC a
finalize (Context ctx) = KMAC $ cshakeFinalize $ cshakeUpdate ctx suffix
  where
    l = cshakeOutputLength (undefined :: a)
    suffix = rightEncode l :: B.Bytes


-- Utilities

bytepad :: ByteArray ba => ba -> Int -> ba
bytepad x w = B.concat [ prefix, x, B.zero padLen ]
  where
    prefix = leftEncode w
    padLen = (w - B.length prefix - B.length x) `mod` w

encodeString :: (ByteArrayAccess bin, ByteArray bout) => bin -> bout
encodeString s = leftEncode (8 * B.length s) `B.append` B.convert s

leftEncode :: ByteArray ba => Int -> ba
leftEncode x = B.cons len digits
  where
    digits = i2osp (toInteger x)
    len    = fromIntegral (B.length digits)

rightEncode :: ByteArray ba => Int -> ba
rightEncode x = B.snoc digits len
  where
    digits = i2osp (toInteger x)
    len    = fromIntegral (B.length digits)
