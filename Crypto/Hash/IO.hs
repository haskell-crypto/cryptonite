-- |
-- Module      : Crypto.Hash.IO
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Generalized impure cryptographic hash interface
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Hash.IO
    (
      HashAlgorithm
    , MutableContext
    , hashMutableInit
    , hashMutableInitWith
    , hashMutableUpdate
    , hashMutableFinalize
    , hashMutableScrub
    ) where

import           Crypto.Hash.Types
import qualified Crypto.Internal.ByteArray as B
import           Foreign.Ptr

newtype MutableContext a = MutableContext B.Bytes
    deriving (B.ByteArrayAccess)

hashMutableInit :: HashAlgorithm alg => IO (MutableContext alg)
hashMutableInit = doInit undefined B.alloc
  where
        doInit :: HashAlgorithm a => a -> (Int -> (Ptr (Context a) -> IO ()) -> IO B.Bytes) -> IO (MutableContext a)
        doInit alg alloc = MutableContext `fmap` alloc (hashInternalContextSize alg) hashInternalInit

hashMutableInitWith :: HashAlgorithm alg => alg -> IO (MutableContext alg)
hashMutableInitWith _ = hashMutableInit

hashMutableUpdate :: (B.ByteArrayAccess ba, HashAlgorithm a) => MutableContext a -> ba -> IO ()
hashMutableUpdate mc dat = doUpdate mc (B.withByteArray mc)
  where doUpdate :: HashAlgorithm a => MutableContext a -> ((Ptr (Context a) -> IO ()) -> IO ()) -> IO ()
        doUpdate _ withCtx =
            withCtx             $ \ctx ->
            B.withByteArray dat $ \d   ->
                hashInternalUpdate ctx d (fromIntegral $ B.length dat)

hashMutableFinalize :: HashAlgorithm a => MutableContext a -> IO (Digest a)
hashMutableFinalize mc = doFinalize undefined (B.withByteArray mc) B.alloc
  where doFinalize :: HashAlgorithm alg
                   => alg
                   -> ((Ptr (Context alg) -> IO ()) -> IO ()) 
                   -> (Int -> (Ptr (Digest alg)  -> IO ()) -> IO B.Bytes)
                   -> IO (Digest alg)
        doFinalize alg withCtx allocDigest = do
            b <- allocDigest (hashDigestSize alg) $ \dig ->
                    withCtx $ \ctx ->
                        hashInternalFinalize ctx dig
            return $ Digest b

-- FIXME not implemented just yet.
hashMutableScrub :: HashAlgorithm a => MutableContext a -> IO ()
hashMutableScrub (MutableContext _) = return ()
