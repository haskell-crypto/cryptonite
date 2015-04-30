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
module Crypto.Hash.Skein256
    (  Skein256_224 (..), Skein256_256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


data Skein256_224 = Skein256_224
    deriving (Show)

instance HashAlgorithm Skein256_224 where
    hashBlockSize  _          = 32
    hashDigestSize _          = 28
    hashInternalContextSize _ = 96
    hashInternalInit p        = c_skein256_init p 224
    hashInternalUpdate        = c_skein256_update
    hashInternalFinalize      = c_skein256_finalize

data Skein256_256 = Skein256_256
    deriving (Show)

instance HashAlgorithm Skein256_256 where
    hashBlockSize  _          = 32
    hashDigestSize _          = 32
    hashInternalContextSize _ = 96
    hashInternalInit p        = c_skein256_init p 256
    hashInternalUpdate        = c_skein256_update
    hashInternalFinalize      = c_skein256_finalize


foreign import ccall unsafe "cryptonite_skein256.h cryptonite_skein256_init"
    c_skein256_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_skein256.h cryptonite_skein256_update"
    c_skein256_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_skein256.h cryptonite_skein256_finalize"
    c_skein256_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
