-- |
-- Module      : Crypto.Hash.SHA512t
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- SHA512t cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.SHA512t
    (  SHA512t_224 (..), SHA512t_256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


data SHA512t_224 = SHA512t_224
    deriving (Show)

instance HashAlgorithm SHA512t_224 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 28
    hashInternalContextSize _ = 264
    hashInternalInit p        = c_sha512t_init p 224
    hashInternalUpdate        = c_sha512t_update
    hashInternalFinalize      = c_sha512t_finalize

data SHA512t_256 = SHA512t_256
    deriving (Show)

instance HashAlgorithm SHA512t_256 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 32
    hashInternalContextSize _ = 264
    hashInternalInit p        = c_sha512t_init p 256
    hashInternalUpdate        = c_sha512t_update
    hashInternalFinalize      = c_sha512t_finalize


foreign import ccall unsafe "cryptonite_sha512t_init"
    c_sha512t_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_sha512t_update"
    c_sha512t_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha512t_finalize"
    c_sha512t_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
