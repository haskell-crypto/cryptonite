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
module Crypto.Hash.SHA512 ( SHA512 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

data SHA512 = SHA512
    deriving (Show)

instance HashAlgorithm SHA512 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 64
    hashInternalContextSize _ = 256
    hashInternalInit          = c_sha512_init
    hashInternalUpdate        = c_sha512_update
    hashInternalFinalize      = c_sha512_finalize

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha512_init"
    c_sha512_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha512.h cryptonite_sha512_update"
    c_sha512_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha512_finalize"
    c_sha512_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
