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
module Crypto.Hash.BLAKE2b
    (  BLAKE2b_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


-- | BLAKE2b (512 bits) cryptographic hash algorithm
data BLAKE2b_512 = BLAKE2b_512
    deriving (Show)

instance HashAlgorithm BLAKE2b_512 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 64
    hashInternalContextSize _ = 361
    hashInternalInit p        = c_blake2b_init p 512
    hashInternalUpdate        = c_blake2b_update
    hashInternalFinalize p    = c_blake2b_finalize p 512


foreign import ccall unsafe "cryptonite_blake2b_init"
    c_blake2b_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_blake2b_update"
    c_blake2b_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2b_finalize"
    c_blake2b_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
