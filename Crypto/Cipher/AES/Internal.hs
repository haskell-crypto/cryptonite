-- |
-- Module      : Crypto.Cipher.AES.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}
module Crypto.Cipher.AES.Internal
    ( AES(..)
    , AESGCM(..)
    , AESOCB(..)
    , c_aes_init
    , c_aes_encrypt_ecb
    , c_aes_encrypt_cbc
    , c_aes_encrypt_xts
    , c_aes_decrypt_ecb
    , c_aes_decrypt_cbc
    , c_aes_decrypt_xts
    , c_aes_encrypt_ctr
    , c_aes_gen_ctr
    , c_aes_gen_ctr_cont
    , c_aes_gcm_init
    , c_aes_gcm_aad
    , c_aes_gcm_encrypt
    , c_aes_gcm_decrypt
    , c_aes_gcm_finish
    , c_aes_ocb_init
    , c_aes_ocb_aad
    , c_aes_ocb_encrypt
    , c_aes_ocb_decrypt
    , c_aes_ocb_finish
    ) where

import Data.Word
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String

import Crypto.Internal.Memory

-- | AES Context (pre-processed key)
newtype AES = AES SecureBytes

-- | AESGCM State
newtype AESGCM = AESGCM SecureBytes

-- | AESOCB State
newtype AESOCB = AESOCB SecureBytes

------------------------------------------------------------------------
foreign import ccall "cryptonite_aes.h cryptonite_aes_initkey"
    c_aes_init :: Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_cbc"
    c_aes_encrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_cbc"
    c_aes_decrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_xts"
    c_aes_encrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_xts"
    c_aes_decrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gen_ctr"
    c_aes_gen_ctr :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_aes.h cryptonite_aes_gen_ctr_cont"
    c_aes_gen_ctr_cont :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_ctr"
    c_aes_encrypt_ctr :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_init"
    c_aes_gcm_init :: Ptr AESGCM -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_aad"
    c_aes_gcm_aad :: Ptr AESGCM -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_encrypt"
    c_aes_gcm_encrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_decrypt"
    c_aes_gcm_decrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr AESGCM -> Ptr AES -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_init"
    c_aes_ocb_init :: Ptr AESOCB -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_aad"
    c_aes_ocb_aad :: Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_encrypt"
    c_aes_ocb_encrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_decrypt"
    c_aes_ocb_decrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_finish"
    c_aes_ocb_finish :: CString -> Ptr AESOCB -> Ptr AES -> IO ()
