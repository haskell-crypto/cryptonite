-- |
-- Module      : Crypto.Hash.Kekkak
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- Kekkak cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.Kekkak
    (  Kekkak_224 (..), Kekkak_256 (..), Kekkak_384 (..), Kekkak_512 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)


data Kekkak_224 = Kekkak_224
    deriving (Show)

instance HashAlgorithm Kekkak_224 where
    hashBlockSize  _          = 144
    hashDigestSize _          = 28
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_kekkak_init p 224
    hashInternalUpdate        = c_kekkak_update
    hashInternalFinalize      = c_kekkak_finalize

data Kekkak_256 = Kekkak_256
    deriving (Show)

instance HashAlgorithm Kekkak_256 where
    hashBlockSize  _          = 136
    hashDigestSize _          = 32
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_kekkak_init p 256
    hashInternalUpdate        = c_kekkak_update
    hashInternalFinalize      = c_kekkak_finalize

data Kekkak_384 = Kekkak_384
    deriving (Show)

instance HashAlgorithm Kekkak_384 where
    hashBlockSize  _          = 104
    hashDigestSize _          = 48
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_kekkak_init p 384
    hashInternalUpdate        = c_kekkak_update
    hashInternalFinalize      = c_kekkak_finalize

data Kekkak_512 = Kekkak_512
    deriving (Show)

instance HashAlgorithm Kekkak_512 where
    hashBlockSize  _          = 72
    hashDigestSize _          = 64
    hashInternalContextSize _ = 360
    hashInternalInit p        = c_kekkak_init p 512
    hashInternalUpdate        = c_kekkak_update
    hashInternalFinalize      = c_kekkak_finalize


foreign import ccall unsafe "cryptonite_kekkak.h cryptonite_kekkak_init"
    c_kekkak_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_kekkak.h cryptonite_kekkak_update"
    c_kekkak_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_kekkak.h cryptonite_kekkak_finalize"
    c_kekkak_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
