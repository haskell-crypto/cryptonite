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
    ) where

import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import           Data.Byteable (Byteable, toBytes)
import           Foreign.Ptr (Ptr)
import qualified Foundation.Array as F
import qualified Foundation       as F

-- | Class representing hashing algorithms.
--
-- The interface presented here is update in place
-- and lowlevel. the Hash module takes care of
-- hidding the mutable interface properly.
class HashAlgorithm a where
    -- | Get the block size of a hash algorithm
    hashBlockSize           :: a -> Int
    -- | Get the digest size of a hash algorithm
    hashDigestSize          :: a -> Int
    -- | Get the size of the context used for a hash algorithm
    hashInternalContextSize :: a -> Int
    --hashAlgorithmFromProxy  :: Proxy a -> a

    -- | Initialize a context pointer to the initial state of a hash algorithm
    hashInternalInit     :: Ptr (Context a) -> IO ()
    -- | Update the context with some raw data
    hashInternalUpdate   :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()
    -- | Finalize the context and set the digest raw memory to the right value
    hashInternalFinalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()

{-
hashContextGetAlgorithm :: HashAlgorithm a => Context a -> a
hashContextGetAlgorithm = undefined
-}

-- | Represent a context for a given hash algorithm.
newtype Context a = Context Bytes
    deriving (ByteArrayAccess,NFData)

-- | Represent a digest for a given hash algorithm.
newtype Digest a = Digest (F.UArray Word8)
    deriving (Eq,Ord,ByteArrayAccess)

instance NFData (Digest a) where
    rnf (Digest u) = u `F.deepseq` ()

instance Show (Digest a) where
    show (Digest bs) = map (toEnum . fromIntegral)
                     $ B.unpack (B.convertToBase B.Base16 bs :: Bytes)

instance Byteable (Digest a) where
    toBytes (Digest bs) = B.pack $ B.unpack (bs :: Bytes)
