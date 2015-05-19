-- |
-- Module      : Crypto.Hash.MD2
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- MD2 cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.MD2 ( MD2 (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

-- | MD2 cryptographic hash algorithm
data MD2 = MD2
    deriving (Show)

instance HashAlgorithm MD2 where
    hashBlockSize  _          = 16
    hashDigestSize _          = 16
    hashInternalContextSize _ = 96
    hashInternalInit          = c_md2_init
    hashInternalUpdate        = c_md2_update
    hashInternalFinalize      = c_md2_finalize

foreign import ccall unsafe "cryptonite_md2_init"
    c_md2_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_md2_update"
    c_md2_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_md2_finalize"
    c_md2_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
