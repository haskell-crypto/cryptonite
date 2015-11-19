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
module Crypto.Hash.BLAKE2s
    (  BLAKE2s_256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


-- | BLAKE2s (256 bits) cryptographic hash algorithm
data BLAKE2s_256 = BLAKE2s_256
    deriving (Show)

instance HashAlgorithm BLAKE2s_256 where
    hashBlockSize  _          = 64
    hashDigestSize _          = 32
    hashInternalContextSize _ = 185
    hashInternalInit p        = c_blake2s_init p 256
    hashInternalUpdate        = c_blake2s_update
    hashInternalFinalize p    = c_blake2s_finalize p 256


foreign import ccall unsafe "cryptonite_blake2s_init"
    c_blake2s_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_blake2s_update"
    c_blake2s_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2s_finalize"
    c_blake2s_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
