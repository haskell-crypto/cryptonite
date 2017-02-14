-- |
-- Module      : Crypto.Hash.Whirlpool
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Whirlpool cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.Whirlpool ( Whirlpool (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | Whirlpool cryptographic hash algorithm
data Whirlpool = Whirlpool
    deriving (Show,Data,Typeable)

instance HashAlgorithm Whirlpool where
    hashBlockSize  _          = 64
    hashDigestSize _          = 64
    hashInternalContextSize _ = 168
    hashInternalInit          = c_whirlpool_init
    hashInternalUpdate        = c_whirlpool_update
    hashInternalFinalize      = c_whirlpool_finalize

foreign import ccall unsafe "cryptonite_whirlpool_init"
    c_whirlpool_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_whirlpool_update"
    c_whirlpool_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_whirlpool_finalize"
    c_whirlpool_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
