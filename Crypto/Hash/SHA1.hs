-- |
-- Module      : Crypto.Hash.SHA1
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA1 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.SHA1 ( SHA1 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA1 cryptographic hash algorithm
data SHA1 = SHA1
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA1 where
    hashBlockSize  _          = 64
    hashDigestSize _          = 20
    hashInternalContextSize _ = 96
    hashInternalInit          = c_sha1_init
    hashInternalUpdate        = c_sha1_update
    hashInternalFinalize      = c_sha1_finalize

foreign import ccall unsafe "cryptonite_sha1_init"
    c_sha1_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha1_update"
    c_sha1_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha1_finalize"
    c_sha1_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
