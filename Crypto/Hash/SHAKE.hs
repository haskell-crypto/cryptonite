-- |
-- Module      : Crypto.Hash.SHAKE
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Module containing the binding functions to work with the
-- SHA3 extendable output functions (SHAKE).
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.Hash.SHAKE
    (  SHAKE128 (..), SHAKE256 (..)
    ) where

import           Crypto.Hash.Types
import           Foreign.Ptr (Ptr)
import           Data.Typeable
import           Data.Word (Word8, Word32)

import           Data.Proxy (Proxy(..))
import           GHC.TypeLits (Nat, KnownNat, natVal)
import           Crypto.Internal.Nat

-- | SHAKE128 (128 bits) extendable output function.  Supports an arbitrary
-- digest size (multiple of 8 bits), to be specified as a type parameter
-- of kind 'Nat'.
--
-- Note: outputs from @'SHAKE128' n@ and @'SHAKE128' m@ for the same input are
-- correlated (one being a prefix of the other).  Results are unrelated to
-- 'SHAKE256' results.
data SHAKE128 (bitlen :: Nat) = SHAKE128
    deriving (Show, Typeable)

instance (IsDivisibleBy8 bitlen, KnownNat bitlen) => HashAlgorithm (SHAKE128 bitlen) where
    type HashBlockSize           (SHAKE128 bitlen)  = 168
    type HashDigestSize          (SHAKE128 bitlen) = Div8 bitlen
    type HashInternalContextSize (SHAKE128 bitlen) = 376
    hashBlockSize  _          = 168
    hashDigestSize _          = byteLen (Proxy :: Proxy bitlen)
    hashInternalContextSize _ = 376
    hashInternalInit p        = c_sha3_init p 128
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize      = shakeFinalizeOutput (Proxy :: Proxy bitlen)

-- | SHAKE256 (256 bits) extendable output function.  Supports an arbitrary
-- digest size (multiple of 8 bits), to be specified as a type parameter
-- of kind 'Nat'.
--
-- Note: outputs from @'SHAKE256' n@ and @'SHAKE256' m@ for the same input are
-- correlated (one being a prefix of the other).  Results are unrelated to
-- 'SHAKE128' results.
data SHAKE256 (bitlen :: Nat) = SHAKE256
    deriving (Show, Typeable)

instance (IsDivisibleBy8 bitlen, KnownNat bitlen) => HashAlgorithm (SHAKE256 bitlen) where
    type HashBlockSize           (SHAKE256 bitlen) = 136
    type HashDigestSize          (SHAKE256 bitlen) = Div8 bitlen
    type HashInternalContextSize (SHAKE256 bitlen) = 344
    hashBlockSize  _          = 136
    hashDigestSize _          = byteLen (Proxy :: Proxy bitlen)
    hashInternalContextSize _ = 344
    hashInternalInit p        = c_sha3_init p 256
    hashInternalUpdate        = c_sha3_update
    hashInternalFinalize      = shakeFinalizeOutput (Proxy :: Proxy bitlen)

shakeFinalizeOutput :: (IsDivisibleBy8 bitlen, KnownNat bitlen)
                    => proxy bitlen
                    -> Ptr (Context a)
                    -> Ptr (Digest a)
                    -> IO ()
shakeFinalizeOutput d ctx dig = do
    c_sha3_finalize_shake ctx
    c_sha3_output ctx dig (byteLen d)

foreign import ccall unsafe "cryptonite_sha3_init"
    c_sha3_init :: Ptr (Context a) -> Word32 -> IO ()

foreign import ccall "cryptonite_sha3_update"
    c_sha3_update :: Ptr (Context a) -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_sha3_finalize_shake"
    c_sha3_finalize_shake :: Ptr (Context a) -> IO ()

foreign import ccall unsafe "cryptonite_sha3_output"
    c_sha3_output :: Ptr (Context a) -> Ptr (Digest a) -> Word32 -> IO ()
