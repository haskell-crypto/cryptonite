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
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE BangPatterns        #-}
module Crypto.Hash
    (
    -- * Types
      Context
    , Digest
    -- * Functions
    , digestFromByteString
    -- * Hash methods parametrized by algorithm
    , hashInitWith
    , hashWith
    -- * Hash methods
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

import           Basement.Types.OffsetSize (CountOf (..))
import           Basement.Block (Block, unsafeFreeze)
import           Basement.Block.Mutable (copyFromPtr, new)
import           Crypto.Internal.Compat (unsafeDoIO)
import           Crypto.Hash.Types
import           Crypto.Hash.Algorithms
import           Foreign.Ptr (Ptr)
import           Crypto.Internal.ByteArray (ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import qualified Data.ByteString.Lazy as L
import           Data.Word (Word8)

-- | Hash a strict bytestring into a digest.
hash :: (ByteArrayAccess ba, HashAlgorithm a) => ba -> Digest a
hash bs = hashFinalize $ hashUpdate hashInit bs

-- | Hash a lazy bytestring into a digest.
hashlazy :: HashAlgorithm a => L.ByteString -> Digest a
hashlazy lbs = hashFinalize $ hashUpdates hashInit (L.toChunks lbs)

-- | Initialize a new context for this hash algorithm
hashInit :: forall a . HashAlgorithm a => Context a
hashInit = Context $ B.allocAndFreeze (hashInternalContextSize (undefined :: a)) $ \(ptr :: Ptr (Context a)) ->
    hashInternalInit ptr

-- | run hashUpdates on one single bytestring and return the updated context.
hashUpdate :: (ByteArrayAccess ba, HashAlgorithm a) => Context a -> ba -> Context a
hashUpdate ctx b
    | B.null b  = ctx
    | otherwise = hashUpdates ctx [b]

-- | Update the context with a list of strict bytestring,
-- and return a new context with the updates.
hashUpdates :: forall a ba . (HashAlgorithm a, ByteArrayAccess ba)
            => Context a
            -> [ba]
            -> Context a
hashUpdates c l
    | null ls   = c
    | otherwise = Context $ B.copyAndFreeze c $ \(ctx :: Ptr (Context a)) ->
        mapM_ (\b -> B.withByteArray b $ \d -> hashInternalUpdate ctx d (fromIntegral $ B.length b)) ls
  where
    ls = filter (not . B.null) l

-- | Finalize a context and return a digest.
hashFinalize :: forall a . HashAlgorithm a
             => Context a
             -> Digest a
hashFinalize !c =
    Digest $ B.allocAndFreeze (hashDigestSize (undefined :: a)) $ \(dig :: Ptr (Digest a)) -> do
        ((!_) :: B.Bytes) <- B.copy c $ \(ctx :: Ptr (Context a)) -> hashInternalFinalize ctx dig
        return ()

-- | Initialize a new context for a specified hash algorithm
hashInitWith :: HashAlgorithm alg => alg -> Context alg
hashInitWith _ = hashInit

-- | Run the 'hash' function but takes an explicit hash algorithm parameter
hashWith :: (ByteArrayAccess ba, HashAlgorithm alg) => alg -> ba -> Digest alg
hashWith _ = hash

-- | Try to transform a bytearray into a Digest of specific algorithm.
--
-- If the digest is not the right size for the algorithm specified, then
-- Nothing is returned.
digestFromByteString :: forall a ba . (HashAlgorithm a, ByteArrayAccess ba) => ba -> Maybe (Digest a)
digestFromByteString = from undefined
  where
        from :: a -> ba -> Maybe (Digest a)
        from alg bs
            | B.length bs == (hashDigestSize alg) = Just $ Digest $ unsafeDoIO $ copyBytes bs
            | otherwise                           = Nothing

        copyBytes :: ba -> IO (Block Word8)
        copyBytes ba = do
            muArray <- new count
            B.withByteArray ba $ \ptr -> copyFromPtr ptr muArray 0 count
            unsafeFreeze muArray
          where
            count = CountOf (B.length ba)
