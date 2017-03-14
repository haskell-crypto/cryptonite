-- |
-- Module      : Crypto.Hash.SHA256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA256 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.SHA256 ( SHA256 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA256 cryptographic hash algorithm
data SHA256 = SHA256
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA256 where
    hashBlockSize  _          = 64
    hashDigestSize _          = 32
    hashInternalContextSize _ = 192
    hashInternalInit          = c_sha256_init
    hashInternalUpdate        = c_sha256_update
    hashInternalFinalize      = c_sha256_finalize

foreign import ccall unsafe "cryptonite_sha256_init"
    c_sha256_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha256_update"
    c_sha256_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha256_finalize"
    c_sha256_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
