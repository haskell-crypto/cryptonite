-- |
-- Module      : Crypto.Hash.MD5
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- MD5 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.MD5 ( MD5 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | MD5 cryptographic hash algorithm
data MD5 = MD5
    deriving (Show,Data,Typeable)

instance HashAlgorithm MD5 where
    hashBlockSize  _          = 64
    hashDigestSize _          = 16
    hashInternalContextSize _ = 96
    hashInternalInit          = c_md5_init
    hashInternalUpdate        = c_md5_update
    hashInternalFinalize      = c_md5_finalize

foreign import ccall unsafe "cryptonite_md5_init"
    c_md5_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_md5_update"
    c_md5_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_md5_finalize"
    c_md5_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
