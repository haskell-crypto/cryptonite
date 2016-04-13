-- |
-- Module      : Crypto.Hash
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Generalized cryptographic hash interface, that you can use with cryptographic hash
-- algorithm that belong to the HashAlgorithm type class.
--
-- > import Crypto.Hash
-- >
-- > sha1 :: ByteString -> Digest SHA1
-- > sha1 = hash
-- >
-- > hexSha3_512 :: ByteString -> String
-- > hexSha3_512 bs = show (hash bs :: Digest SHA3_512)
--
module Crypto.Hash
    (
    -- * Types
      Context
    , Digest
    -- * Functions
    , digestFromByteString
    -- * hash methods parametrized by algorithm
    , hashInitWith
    , hashWith
    -- * hash methods
    , hashInit
    , hashUpdates
    , hashUpdate
    , hashFinalize
    , hashBlockSize
    , hashDigestSize
    , hash
    , hashlazy
    -- * Hash algorithms
    , module Crypto.Hash.Algorithms
    ) where

import           Control.Monad
import           Crypto.Hash.Types
import           Crypto.Hash.Algorithms
import           Foreign.Ptr (Ptr)
import           Crypto.Internal.ByteArray (ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import qualified Data.ByteString.Lazy as L

-- | Hash a strict bytestring into a digest.
hash :: (ByteArrayAccess ba, HashAlgorithm a) => ba -> Digest a
hash bs = hashFinalize $ hashUpdate hashInit bs

-- | Hash a lazy bytestring into a digest.
hashlazy :: HashAlgorithm a => L.ByteString -> Digest a
hashlazy lbs = hashFinalize $ hashUpdates hashInit (L.toChunks lbs)

-- | Initialize a new context for this hash algorithm
hashInit :: HashAlgorithm a
         => Context a
hashInit = doInit undefined B.allocAndFreeze
  where
        doInit :: HashAlgorithm a => a -> (Int -> (Ptr (Context a) -> IO ()) -> B.Bytes) -> Context a
        doInit alg alloc = Context $ alloc (hashInternalContextSize alg) hashInternalInit
{-# NOINLINE hashInit #-}

-- | run hashUpdates on one single bytestring and return the updated context.
hashUpdate :: (ByteArrayAccess ba, HashAlgorithm a) => Context a -> ba -> Context a
hashUpdate ctx b = hashUpdates ctx [b]

-- | Update the context with a list of strict bytestring,
-- and return a new context with the updates.
hashUpdates :: (HashAlgorithm a, ByteArrayAccess ba)
            => Context a
            -> [ba]
            -> Context a
hashUpdates c l = doUpdates (B.copyAndFreeze c)
  where doUpdates :: HashAlgorithm a => ((Ptr (Context a) -> IO ()) -> B.Bytes) -> Context a
        doUpdates copy = Context $ copy $ \ctx ->
            mapM_ (\b -> B.withByteArray b $ \d -> hashInternalUpdate ctx d (fromIntegral $ B.length b)) l
{-# NOINLINE hashUpdates #-}

-- | Finalize a context and return a digest.
hashFinalize :: HashAlgorithm a
             => Context a
             -> Digest a
hashFinalize c = doFinalize undefined (B.copy c) (B.allocAndFreeze)
  where doFinalize :: HashAlgorithm alg
                   => alg
                   -> ((Ptr (Context alg) -> IO ()) -> IO B.Bytes)
                   -> (Int -> (Ptr (Digest alg)  -> IO ()) -> B.Bytes)
                   -> Digest alg
        doFinalize alg copy allocDigest =
            Digest $ allocDigest (hashDigestSize alg) $ \dig ->
                (void $ copy $ \ctx -> hashInternalFinalize ctx dig)
{-# NOINLINE hashFinalize #-}

-- | Initialize a new context for a specified hash algorithm
hashInitWith :: HashAlgorithm alg => alg -> Context alg
hashInitWith _ = hashInit

-- | Run the 'hash' function but takes an explicit hash algorithm parameter
hashWith :: (ByteArrayAccess ba, HashAlgorithm alg) => alg -> ba -> Digest alg
hashWith _ = hash


