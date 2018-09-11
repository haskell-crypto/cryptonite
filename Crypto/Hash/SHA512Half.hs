-- |
-- Module      : Crypto.Hash.SHA512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Module containing the binding functions to work with the
-- SHA512 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash.SHA512Half ( SHA512Half (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | SHA512Half cryptographic hash algorithm
data SHA512Half = SHA512Half
    deriving (Show,Data,Typeable)

instance HashAlgorithm SHA512Half where
    type HashBlockSize           SHA512Half = 128
    type HashDigestSize          SHA512Half = 32
    type HashInternalContextSize SHA512Half = 256
    hashBlockSize  _          = 128
    hashDigestSize _          = 32
    hashInternalContextSize _ = 256
    hashInternalInit          = c_sha512half_init
    hashInternalUpdate        = c_sha512half_update
    hashInternalFinalize      = c_sha512half_finalize

foreign import ccall unsafe "cryptonite_sha512half_init"
    c_sha512half_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha512half_update"
    c_sha512half_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512half_finalize"
    c_sha512half_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
