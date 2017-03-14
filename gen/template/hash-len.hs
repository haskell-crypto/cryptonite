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
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Hash.%%MODULENAME%%
    ( %{CUSTOMIZABLE%}%%COMMA%% %%MODULENAME%%_%%CUSTOM_BITSIZE%% (..)%{CUSTOMIZABLE%}
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

%{CUSTOMIZABLE%}
-- | %%MODULENAME%% (%%CUSTOM_BITSIZE%% bits) cryptographic hash algorithm
data %%MODULENAME%%_%%CUSTOM_BITSIZE%% = %%MODULENAME%%_%%CUSTOM_BITSIZE%%
    deriving (Show,Data,Typeable)

instance HashAlgorithm %%MODULENAME%%_%%CUSTOM_BITSIZE%% where
    hashBlockSize  _          = %%CUSTOM_BLOCK_SIZE_BYTES%%
    hashDigestSize _          = %%CUSTOM_DIGEST_SIZE_BYTES%%
    hashInternalContextSize _ = %%CUSTOM_CTX_SIZE_BYTES%%
    hashInternalInit p        = c_%%HASHNAME%%_init p %%CUSTOM_BITSIZE%%
    hashInternalUpdate        = c_%%HASHNAME%%_update
    hashInternalFinalize p    = c_%%HASHNAME%%_finalize p %%CUSTOM_BITSIZE%%
%{CUSTOMIZABLE%}

foreign import ccall unsafe "cryptonite_%%HASHNAME%%_init"
    c_%%HASHNAME%%_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_%%HASHNAME%%_update"
    c_%%HASHNAME%%_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_%%HASHNAME%%_finalize"
    c_%%HASHNAME%%_finalize :: Ptr (Context a) -> Word32 -> Ptr (Digest a) -> IO ()
