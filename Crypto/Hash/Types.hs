-- |
-- Module      : Crypto.Hash.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash types definitions
--
module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , Context(..)
    , Digest(..)
    -- * deprecated
    , contextToByteString
    , digestToByteString
    )
    where

import Data.ByteString (ByteString)
import Data.Byteable
import qualified Data.ByteString.Char8 as BC
import Crypto.Hash.Utils (toHex)

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
    -- | Block size in bytes the hash algorithm operates on
    hashBlockSize :: Context a -> Int

    -- | Initialize a new context for this hash algorithm
    hashInit     :: Context a

    -- | Update the context with a list of strict bytestring,
    -- and return a new context with the updates.
    hashUpdates  :: Context a -> [ByteString] -> Context a

    -- | Finalize a context and return a digest.
    hashFinalize :: Context a -> Digest a

    -- | Try to convert a binary digest bytestring to a digest.
    digestFromByteString :: ByteString -> Maybe (Digest a)

-- | Represent a context for a given hash algorithm.
newtype Context a = Context ByteString

instance Byteable (Context a) where
    toBytes (Context bs) = bs

-- | return the binary bytestring. deprecated use toBytes.
contextToByteString :: Context a -> ByteString
contextToByteString = toBytes

-- | Represent a digest for a given hash algorithm.
newtype Digest a = Digest ByteString
    deriving (Eq,Ord)

instance Byteable (Digest a) where
    toBytes (Digest bs) = bs

-- | return the binary bytestring. deprecated use toBytes.
{-# DEPRECATED digestToByteString "use toBytes from byteable:Data.Byteable" #-}
digestToByteString :: Digest a -> ByteString
digestToByteString = toBytes

instance Show (Digest a) where
    show (Digest bs) = BC.unpack $ toHex bs
