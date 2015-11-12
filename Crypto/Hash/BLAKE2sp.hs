-- |
-- Module      : Crypto.Hash.BLAKE2sp
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- BLAKE2sp cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.BLAKE2sp ( BLAKE2sp (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

-- | BLAKE2sp cryptographic hash algorithm
data BLAKE2sp = BLAKE2sp
    deriving (Show)

instance HashAlgorithm BLAKE2sp where
    hashBlockSize  _          = 64
    hashDigestSize _          = 32
    hashInternalContextSize _ = 2185
    hashInternalInit          = c_blake2sp_init
    hashInternalUpdate        = c_blake2sp_update
    hashInternalFinalize      = c_blake2sp_finalize

foreign import ccall unsafe "cryptonite_blake2sp_init"
    c_blake2sp_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_blake2sp_update"
    c_blake2sp_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2sp_finalize"
    c_blake2sp_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
