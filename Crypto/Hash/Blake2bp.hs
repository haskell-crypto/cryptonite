-- |
-- Module      : Crypto.Hash.Blake2bp
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Blake2bp cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.Blake2bp
    (  Blake2bp_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)


-- | Blake2bp, 4-way parallel (512 bits) cryptographic hash algorithm
data Blake2bp_512 = Blake2bp_512
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2bp_512 where
    hashBlockSize  _          = 128
    hashDigestSize _          = 64
    hashInternalContextSize _ = 2325
    hashInternalInit p        = c_blake2sp_init p 512
    hashInternalUpdate        = c_blake2sp_update
    hashInternalFinalize p    = c_blake2sp_finalize p 512


foreign import ccall unsafe "cryptonite_blake2sp_init"
    c_blake2sp_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_blake2sp_update"
    c_blake2sp_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2sp_finalize"
    c_blake2sp_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
