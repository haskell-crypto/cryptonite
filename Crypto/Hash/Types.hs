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
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , HashAlgorithm'(..)
    , Context(..)
    , Digest(..)
    ) where

import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Imports
import           Data.Proxy
import           Foreign.Ptr (Ptr)
import qualified Foundation       as F
import qualified Foundation.Array as F
import           GHC.TypeLits (Nat, KnownNat, natVal)

-- | Class representing hashing algorithms.
--
-- The interface presented here is update in place
-- and lowlevel. the Hash module takes care of
-- hidding the mutable interface properly.
class HashAlgorithm a where

    -- | Get the block size of a hash algorithm
    hashBlockSize         :: a -> Int
    default hashBlockSize :: HashAlgorithm' a => a -> Int
    hashBlockSize _ = hashBlockSize' (Proxy :: Proxy a)

    -- | Get the digest size of a hash algorithm
    hashDigestSize         :: a -> Int
    default hashDigestSize :: HashAlgorithm' a => a -> Int
    hashDigestSize _ = hashDigestSize' (Proxy :: Proxy a)

    -- | Get the size of the context used for a hash algorithm
    hashInternalContextSize         :: a -> Int
    default hashInternalContextSize :: HashAlgorithm' a => a -> Int
    hashInternalContextSize _ = hashInternalContextSize' (Proxy :: Proxy a)
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

class
    ( KnownNat (HashBlockSize a)
    , KnownNat (HashDigestSize a)
    , KnownNat (HashInternalContextSize a)
    , HashAlgorithm a
    ) => HashAlgorithm' a
  where
    -- | Get the block size of a hash algorithm
    type HashBlockSize           a :: Nat
    -- | Get the digest size of a hash algorithm
    type HashDigestSize          a :: Nat
    -- | Get the size of the context used for a hash algorithm
    type HashInternalContextSize a :: Nat

hashBlockSize' :: forall a . HashAlgorithm' a => Proxy a -> Int
hashBlockSize' _ = fromInteger (natVal (Proxy :: Proxy (HashBlockSize a)))

hashDigestSize' :: forall a . HashAlgorithm' a => Proxy a -> Int
hashDigestSize' _ = fromInteger (natVal (Proxy :: Proxy (HashDigestSize a)))

hashInternalContextSize' :: forall a . HashAlgorithm' a => Proxy a -> Int
hashInternalContextSize' _ =
    fromInteger (natVal (Proxy :: Proxy (HashInternalContextSize a)))

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
