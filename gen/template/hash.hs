-- |
-- Module      : Crypto.Hash.%%MODULENAME%%
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the binding functions to work with the
-- %%MODULENAME%% cryptographic hash.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Hash.%%MODULENAME%% ( %%MODULENAME%% (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Word (Word8, Word32)

data %%MODULENAME%% = %%MODULENAME%%
    deriving (Show)

instance HashAlgorithm %%MODULENAME%% where
    hashBlockSize  _          = %%BLOCKLEN%%
    hashDigestSize _          = %%DIGESTSIZE%%
    hashInternalContextSize _ = %%SIZECTX%%
    hashInternalInit          = c_%%HASHNAME%%_init
    hashInternalUpdate        = c_%%HASHNAME%%_update
    hashInternalFinalize      = c_%%HASHNAME%%_finalize

foreign import ccall unsafe "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_init"
    c_%%HASHNAME%%_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_update"
    c_%%HASHNAME%%_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_%%HEADER_FILE%% cryptonite_%%HASHNAME%%_finalize"
    c_%%HASHNAME%%_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
