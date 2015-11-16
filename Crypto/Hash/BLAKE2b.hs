-- |
-- Module      : Crypto.Hash.BLAKE2b
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- BLAKE2b cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.BLAKE2b ( BLAKE2b (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

-- | BLAKE2b cryptographic hash algorithm
data BLAKE2b = BLAKE2b
    deriving (Show)

instance HashAlgorithm BLAKE2b where
    hashBlockSize  _          = 128
    hashDigestSize _          = 64
    hashInternalContextSize _ = 361
    hashInternalInit          = c_blake2b_init
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize      = c_blake2b_finalize

foreign import ccall unsafe "cryptonite_blake2b_init"
    c_blake2b_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_blake2b_update"
    c_blake2b_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2b_finalize"
    c_blake2b_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
