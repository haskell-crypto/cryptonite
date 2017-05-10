-- |
-- Module      : Crypto.Hash.Blake2sp
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Blake2sp cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash.Blake2sp
    (  Blake2sp_224 (..), Blake2sp_256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)


-- | Blake2sp (224 bits) cryptographic hash algorithm
data Blake2sp_224 = Blake2sp_224
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2sp_224 where
    hashInternalInit p        = c_blake2sp_init p 224
    hashInternalUpdate        = c_blake2sp_update
    hashInternalFinalize p    = c_blake2sp_finalize p 224

instance HashAlgorithm' Blake2sp_224 where
    type HashBlockSize           Blake2sp_224 = 64
    type HashDigestSize          Blake2sp_224 = 28
    type HashInternalContextSize Blake2sp_224 = 2185

-- | Blake2sp (256 bits) cryptographic hash algorithm
data Blake2sp_256 = Blake2sp_256
    deriving (Show,Data,Typeable)

instance HashAlgorithm Blake2sp_256 where
    hashInternalInit p        = c_blake2sp_init p 256
    hashInternalUpdate        = c_blake2sp_update
    hashInternalFinalize p    = c_blake2sp_finalize p 256

instance HashAlgorithm' Blake2sp_256 where
    type HashBlockSize           Blake2sp_256 = 64
    type HashDigestSize          Blake2sp_256 = 32
    type HashInternalContextSize Blake2sp_256 = 2185


foreign import ccall unsafe "cryptonite_blake2sp_init"
    c_blake2sp_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_blake2sp_update"
    c_blake2sp_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_blake2sp_finalize"
    c_blake2sp_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
