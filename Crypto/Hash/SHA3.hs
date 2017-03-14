-- |
-- Module      : Crypto.Hash.SHA3
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA3 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.SHA3
    (  SHA3_224 (..), SHA3_256 (..), SHA3_384 (..), SHA3_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA3 (224 bits) cryptographic hash algorithm
data SHA3_224 = SHA3_224
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA3_224 where
    hashBlockSize  _          = 144
    hashDigestSize _          = 28
    hashInternalContextSize _ = 352
    hashInternalInit p        = c_sha3_init p 224
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize p    = c_sha3_finalize p 224

-- | SHA3 (256 bits) cryptographic hash algorithm
data SHA3_256 = SHA3_256
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA3_256 where
    hashBlockSize  _          = 136
    hashDigestSize _          = 32
    hashInternalContextSize _ = 344
    hashInternalInit p        = c_sha3_init p 256
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize p    = c_sha3_finalize p 256

-- | SHA3 (384 bits) cryptographic hash algorithm
data SHA3_384 = SHA3_384
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA3_384 where
    hashBlockSize  _          = 104
    hashDigestSize _          = 48
    hashInternalContextSize _ = 312
    hashInternalInit p        = c_sha3_init p 384
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize p    = c_sha3_finalize p 384

-- | SHA3 (512 bits) cryptographic hash algorithm
data SHA3_512 = SHA3_512
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA3_512 where
    hashBlockSize  _          = 72
    hashDigestSize _          = 64
    hashInternalContextSize _ = 280
    hashInternalInit p        = c_sha3_init p 512
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize p    = c_sha3_finalize p 512

foreign import ccall unsafe "cryptonite_sha3_init"
    c_sha3_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_sha3_update"
    c_sha3_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha3_finalize"
    c_sha3_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
