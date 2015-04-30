-- |
-- Module      : Crypto.Hash.SHA384
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA384 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.SHA384 ( SHA384 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

data SHA384 = SHA384
    deriving (Show)

instance HashAlgorithm SHA384 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 48
    hashInternalContextSize _ = 256
    hashInternalInit          = c_sha384_init
    hashInternalUpdate        = c_sha384_update
    hashInternalFinalize      = c_sha384_finalize

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha384_init"
    c_sha384_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_sha512.h cryptonite_sha384_update"
    c_sha384_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha384_finalize"
    c_sha384_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
