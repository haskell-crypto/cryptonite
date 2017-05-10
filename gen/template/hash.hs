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
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash.%%MODULENAME%% ( %%MODULENAME%% (..) ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Data
import           Data.Typeable
import           Data.Word (Word8, Word32)

-- | %%MODULENAME%% cryptographic hash algorithm
data %%MODULENAME%% = %%MODULENAME%%
    deriving (Show,Data,Typeable)

instance HashAlgorithm %%MODULENAME%% where
    hashInternalInit          = c_%%HASHNAME%%_init
    hashInternalUpdate        = c_%%HASHNAME%%_update
    hashInternalFinalize      = c_%%HASHNAME%%_finalize

instance HashAlgorithm' %%MODULENAME%% where
    type HashBlockSize           %%MODULENAME%% = %%BLOCK_SIZE_BYTES%%
    type HashDigestSize          %%MODULENAME%% = %%DIGEST_SIZE_BYTES%%
    type HashInternalContextSize %%MODULENAME%% = %%CTX_SIZE_BYTES%%

foreign import ccall unsafe "cryptonite_%%HASHNAME%%_init"
    c_%%HASHNAME%%_init :: Ptr (Context a)-> IO ()

foreign import ccall "cryptonite_%%HASHNAME%%_update"
    c_%%HASHNAME%%_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_%%HASHNAME%%_finalize"
    c_%%HASHNAME%%_finalize :: Ptr (Context a) -> Ptr (Digest a) -> IO ()
