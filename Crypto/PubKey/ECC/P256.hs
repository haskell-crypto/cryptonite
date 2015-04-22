-- |
-- Module      : Crypto.PubKey.ECC.P256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- P256 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
module Crypto.PubKey.ECC.P256
    ( SecretKey
    , PublicKey
    ) where

import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.Memory
import           Crypto.Internal.ByteArray
import           Crypto.Error

-- | A P256 Secret key
newtype SecretKey = SecretKey P256Num
    deriving (Eq,ByteArrayAccess)

-- | A P256 public key
data PublicKey = PublicKey P256Num P256Num
    deriving (Show,Eq)

newtype P256Num = P256Num SecureBytes
    deriving (Eq,ByteArrayAccess)

instance Show P256Num where
    show _ = "P256Num"

publicKeySize :: Int
publicKeySize = 32

secretKeySize :: Int
secretKeySize = 32

type P256Digit = Word32

foreign import ccall "cryptonite_p256_init"
    ccryptonite_p256_init :: Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_clear"
    ccryptonite_p256_clear :: Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_add"
    ccryptonite_p256_add :: Ptr P256Num -> Ptr P256Num -> Ptr P256Num -> IO CInt
foreign import ccall "cryptonite_p256_sub"
    ccryptonite_p256_sub :: Ptr P256Num -> Ptr P256Num -> Ptr P256Num -> IO CInt
foreign import ccall "cryptonite_p256_cmp"
    ccryptonite_p256_cmp :: Ptr P256Num -> Ptr P256Num -> IO CInt
foreign import ccall "cryptonite_p256_mod"
    ccryptonite_p256_mod :: Ptr P256Num -> Ptr P256Num -> Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_modmul"
    ccryptonite_p256_modmul :: Ptr P256Num -> Ptr P256Num -> P256Digit -> Ptr P256Num -> Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_modinv"
    ccryptonite_p256_modinv :: Ptr P256Num -> Ptr P256Num -> Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_modinv_vartime"
    ccryptonite_p256_modinv_vartime :: Ptr P256Num -> Ptr P256Num -> Ptr P256Num -> IO ()
foreign import ccall "cryptonite_p256_base_point_mul"
    ccryptonite_p256_basepoint_mul :: Ptr P256Num
                                   -> Ptr P256Num -> Ptr P256Num
                                   -> IO ()
foreign import ccall "cryptonite_p256_point_mul"
    ccryptonite_p256_point_mul :: Ptr P256Num
                               -> Ptr P256Num -> Ptr P256Num
                               -> Ptr P256Num -> Ptr P256Num
                               -> IO ()
foreign import ccall "cryptonite_p256_is_valid_point"
    ccryptonite_p256_is_valid_point :: Ptr P256Num -> Ptr P256Num -> IO CInt

foreign import ccall "cryptonite_p256_to_bin"
    ccryptonite_p256_to_bin :: Ptr P256Num -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_p256_from_bin"
    ccryptonite_p256_from_bin :: Ptr Word8 -> Ptr P256Num -> IO ()
