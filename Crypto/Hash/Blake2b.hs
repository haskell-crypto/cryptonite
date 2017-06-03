-- |
-- Module      : Crypto.Hash.Blake2b
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Blake2b cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.Blake2b
    (  Blake2b_160 (..), Blake2b_224 (..), Blake2b_256 (..), Blake2b_384 (..), Blake2b_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)


-- | Blake2b, or just Blake2 (160 bits) cryptographic hash algorithm
data Blake2b_160 = Blake2b_160
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2b_160 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 20
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 160
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 160

-- | Blake2b, or just Blake2 (224 bits) cryptographic hash algorithm
data Blake2b_224 = Blake2b_224
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2b_224 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 28
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 224
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 224

-- | Blake2b, or just Blake2 (256 bits) cryptographic hash algorithm
data Blake2b_256 = Blake2b_256
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2b_256 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 32
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 256
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 256

-- | Blake2b, or just Blake2 (384 bits) cryptographic hash algorithm
data Blake2b_384 = Blake2b_384
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2b_384 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 48
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 384
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 384

-- | Blake2b, or just Blake2 (512 bits) cryptographic hash algorithm
data Blake2b_512 = Blake2b_512
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2b_512 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 64
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 512
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 512


foreign import ccall unsafe "cryptonite_blake2b_init"
    c_blake2b_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_blake2b_update"
    c_blake2b_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2b_finalize"
    c_blake2b_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
