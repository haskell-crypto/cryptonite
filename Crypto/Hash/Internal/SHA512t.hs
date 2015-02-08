{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Hash.SHA512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the internal functions to work with the
-- SHA512t cryptographic hash (FIPS-180-4 truncated SHA512).
--
-- it is recommended to import this module qualified.
--
module Crypto.Hash.Internal.SHA512t
    (
    -- * Internal IO hash functions
      internalInit
    , internalInitAt
    ) where

import Foreign.Ptr
import Data.Word
import Crypto.Hash.Internal.SHA512 (withCtxNew, Ctx)

foreign import ccall unsafe "cryptonite_sha512.h cryptonite_sha512_init_t"
    c_sha512_init_t :: Ptr Ctx -> Word32 -> IO ()

-- | init a context using FIPS 180-4 for truncated SHA512
internalInitAt :: Int -> Ptr Ctx -> IO ()
internalInitAt hashlen ptr = c_sha512_init_t ptr (fromIntegral hashlen)

-- | init a context using FIPS 180-4 for truncated SHA512
internalInit :: Int -> IO Ctx
internalInit hashlen = withCtxNew (internalInitAt hashlen)
