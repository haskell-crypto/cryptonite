-- |
-- Module      : Crypto.Hash.SHA512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA512 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash.SHA512 ( SHA512 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA512 cryptographic hash algorithm
data SHA512 = SHA512
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA512 where
    hashInternalInit          = c_sha512_init
    hashInternalUpdate        = c_sha512_update
    hashInternalFinalize      = c_sha512_finalize

instance HashAlgorithm' SHA512 where
    type HashBlockSize           SHA512 = 128
    type HashDigestSize          SHA512 = 64
    type HashInternalContextSize SHA512 = 256

foreign import ccall unsafe "cryptonite_sha512_init"
    c_sha512_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha512_update"
    c_sha512_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512_finalize"
    c_sha512_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
