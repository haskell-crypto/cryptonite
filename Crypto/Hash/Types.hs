-- |
-- Module      : Crypto.Hash.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash types definitions
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , Context(..)
    , Digest(..)
    )
    where

import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import           Data.Word
import           Foreign.Ptr (Ptr)

-- | Class representing hashing algorithms.
--
-- The hash algorithm is built over 3 primitives:
--
-- * init     : create a new hashing context
--
-- * updates  : update the hashing context with some strict bytestrings
--              and return the new context
--
-- * finalize : finalize the context into a digest
--
class HashAlgorithm a where
    hashBlockSize           :: a -> Int
    hashDigestSize          :: a -> Int
    hashInternalContextSize :: a -> Int
    --hashAlgorithmFromProxy  :: Proxy a -> a

    hashInternalInit     :: Ptr (Context a) -> IO ()
    hashInternalUpdate   :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()
    hashInternalFinalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()

{-
hashContextGetAlgorithm :: HashAlgorithm a => Context a -> a
hashContextGetAlgorithm = undefined
-}

-- | Represent a context for a given hash algorithm.
newtype Context a = Context Bytes
    deriving (ByteArrayAccess)

-- | Represent a digest for a given hash algorithm.
newtype Digest a = Digest Bytes
    deriving (Eq,ByteArrayAccess)

instance Show (Digest a) where
    show (Digest bs) = show (B.convertHex bs :: Bytes)
