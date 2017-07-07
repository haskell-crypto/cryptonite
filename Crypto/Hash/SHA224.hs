-- |
-- Module      : Crypto.Hash.SHA224
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA224 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash.SHA224 ( SHA224 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA224 cryptographic hash algorithm
data SHA224 = SHA224
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA224 where
    hashInternalInit          = c_sha224_init
    hashInternalUpdate        = c_sha224_update
    hashInternalFinalize      = c_sha224_finalize

instance HashAlgorithm' SHA224 where
    type HashBlockSize           SHA224 = 64
    type HashDigestSize          SHA224 = 28
    type HashInternalContextSize SHA224 = 192

foreign import ccall unsafe "cryptonite_sha224_init"
    c_sha224_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha224_update"
    c_sha224_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha224_finalize"
    c_sha224_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
