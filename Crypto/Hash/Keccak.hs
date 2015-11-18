-- |
-- Module      : Crypto.Hash.Keccak
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Keccak cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.Keccak
    (  Keccak_224 (..), Keccak_256 (..), Keccak_384 (..), Keccak_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


-- | Keccak (224 bits) cryptographic hash algorithm
data Keccak_224 = Keccak_224
    deriving (Show)

instance HashAlgorithm Keccak_224 where
    hashBlockSize  _          = 144
    hashDigestSize _          = 28
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_keccak_init p 224
    hashInternalUpdate        = c_keccak_update
    hashInternalFinalize      = c_keccak_finalize

-- | Keccak (256 bits) cryptographic hash algorithm
data Keccak_256 = Keccak_256
    deriving (Show)

instance HashAlgorithm Keccak_256 where
    hashBlockSize  _          = 136
    hashDigestSize _          = 32
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_keccak_init p 256
    hashInternalUpdate        = c_keccak_update
    hashInternalFinalize      = c_keccak_finalize

-- | Keccak (384 bits) cryptographic hash algorithm
data Keccak_384 = Keccak_384
    deriving (Show)

instance HashAlgorithm Keccak_384 where
    hashBlockSize  _          = 104
    hashDigestSize _          = 48
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_keccak_init p 384
    hashInternalUpdate        = c_keccak_update
    hashInternalFinalize      = c_keccak_finalize

-- | Keccak (512 bits) cryptographic hash algorithm
data Keccak_512 = Keccak_512
    deriving (Show)

instance HashAlgorithm Keccak_512 where
    hashBlockSize  _          = 72
    hashDigestSize _          = 64
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_keccak_init p 512
    hashInternalUpdate        = c_keccak_update
    hashInternalFinalize      = c_keccak_finalize


foreign import ccall unsafe "cryptonite_keccak_init"
    c_keccak_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_keccak_update"
    c_keccak_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_keccak_finalize"
    c_keccak_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
