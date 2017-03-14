-- |
-- Module      : Crypto.Hash.Skein256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Skein256 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.Skein256
    (  Skein256_224 (..), Skein256_256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)


-- | Skein256 (224 bits) cryptographic hash algorithm
data Skein256_224 = Skein256_224
    deriving (Show,Data,Typeable)

instance HashAlgorithm Skein256_224 where
    hashBlockSize  _          = 32
    hashDigestSize _          = 28
    hashInternalContextSize _ = 96
    hashInternalInit p        = c_skein256_init p 224
    hashInternalUpdate        = c_skein256_update
    hashInternalFinalize p    = c_skein256_finalize p 224

-- | Skein256 (256 bits) cryptographic hash algorithm
data Skein256_256 = Skein256_256
    deriving (Show,Data,Typeable)

instance HashAlgorithm Skein256_256 where
    hashBlockSize  _          = 32
    hashDigestSize _          = 32
    hashInternalContextSize _ = 96
    hashInternalInit p        = c_skein256_init p 256
    hashInternalUpdate        = c_skein256_update
    hashInternalFinalize p    = c_skein256_finalize p 256


foreign import ccall unsafe "cryptonite_skein256_init"
    c_skein256_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_skein256_update"
    c_skein256_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_skein256_finalize"
    c_skein256_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
