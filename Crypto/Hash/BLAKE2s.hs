-- |
-- Module      : Crypto.Hash.BLAKE2s
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- BLAKE2s cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.BLAKE2s ( BLAKE2s (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

-- | BLAKE2s cryptographic hash algorithm
data BLAKE2s = BLAKE2s
    deriving (Show)

instance HashAlgorithm BLAKE2s where
    hashBlockSize  _          = 64
    hashDigestSize _          = 32
    hashInternalContextSize _ = 185
    hashInternalInit          = c_blake2s_init
    hashInternalUpdate        = c_blake2s_update
    hashInternalFinalize      = c_blake2s_finalize

foreign import ccall unsafe "cryptonite_blake2s_init"
    c_blake2s_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_blake2s_update"
    c_blake2s_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2s_finalize"
    c_blake2s_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
