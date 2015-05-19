-- |
-- Module      : Crypto.Hash.MD4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- MD4 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.MD4 ( MD4 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

-- | MD4 cryptographic hash algorithm
data MD4 = MD4
    deriving (Show)

instance HashAlgorithm MD4 where
    hashBlockSize  _          = 64
    hashDigestSize _          = 16
    hashInternalContextSize _ = 96
    hashInternalInit          = c_md4_init
    hashInternalUpdate        = c_md4_update
    hashInternalFinalize      = c_md4_finalize

foreign import ccall unsafe "cryptonite_md4_init"
    c_md4_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_md4_update"
    c_md4_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_md4_finalize"
    c_md4_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
