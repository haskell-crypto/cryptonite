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
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , Context(..)
    , Digest(..)
    , digestFromByteString
    ) where

import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import           Foreign.Ptr (Ptr)
import          qualified Data.ByteString.Char8 as C
import Data.Monoid

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
newtype Digest a = Digest Bytes
    deriving (Eq,Ord,ByteArrayAccess,NFData)

instance Show (Digest a) where
    show (Digest bs) = C.unpack $ B.convertToBase B.Base16 bs

instance HashAlgorithm a => Read (Digest a) where
    readsPrec _ x = case B.convertFromBase B.Base16 . C.pack $ x of
        Left _ -> [] -- failed conversion
        Right (y :: B.Bytes) -> case digestFromByteString y of 
            Nothing -> [] -- wrong length
            Just z -> [(z,"")]

-- | Try to transform a bytearray into a Digest of specific algorithm.
--
-- If the digest is not the right size for the algorithm specified, then
-- Nothing is returned.
digestFromByteString :: (HashAlgorithm a, ByteArrayAccess ba) => ba -> Maybe (Digest a)
digestFromByteString = from undefined
  where
        from :: (HashAlgorithm a, ByteArrayAccess ba) => a -> ba -> Maybe (Digest a)
        from alg bs
            | B.length bs == (hashDigestSize alg) = (Just $ Digest $ B.convert bs)
            | otherwise                           = Nothing
