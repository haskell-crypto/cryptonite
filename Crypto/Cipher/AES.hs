    -- |
-- Module      : Crypto.Cipher.AES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
{-# LANGUAGE CPP #-}
module Crypto.Cipher.AES
    ( AES128
    , AES192
    , AES256
    ) where

import Crypto.Cipher.Types
import Crypto.Cipher.AES.Primitive

-- | AES with 128 bit key
newtype AES128 = AES128 AES

-- | AES with 192 bit key
newtype AES192 = AES192 AES

-- | AES with 256 bit key
newtype AES256 = AES256 AES

instance Cipher AES128 where
    cipherName    _ = "AES128"
    cipherKeySize _ = KeySizeFixed 16
    cipherInit k    = AES128 `fmap` initAES k

instance Cipher AES192 where
    cipherName    _ = "AES192"
    cipherKeySize _ = KeySizeFixed 24
    cipherInit k    = AES192 `fmap` initAES k

instance Cipher AES256 where
    cipherName    _ = "AES256"
    cipherKeySize _ = KeySizeFixed 32
    cipherInit k    = AES256 `fmap` initAES k


{-}
instance AEADModeImpl AES AESGCM where
    aeadStateAppendHeader _ = gcmAppendAAD
    aeadStateEncrypt = gcmAppendEncrypt
    aeadStateDecrypt = gcmAppendDecrypt
    aeadStateFinalize = gcmFinish

instance AEADModeImpl AES AESOCB where
    aeadStateAppendHeader = ocbAppendAAD
    aeadStateEncrypt = ocbAppendEncrypt
    aeadStateDecrypt = ocbAppendDecrypt
    aeadStateFinalize = ocbFinish
    -}

#define INSTANCE_BLOCKCIPHER(CSTR) \
instance BlockCipher CSTR where \
    { blockSize _ = 16 \
    ; ecbEncrypt (CSTR aes) = ecbEncryptLegacy encryptECB aes \
    ; ecbDecrypt (CSTR aes) = ecbDecryptLegacy decryptECB aes \
    ; cbcEncrypt (CSTR aes) = encryptCBC aes \
    ; cbcDecrypt (CSTR aes) = decryptCBC aes \
    ; ctrCombine (CSTR aes) = encryptCTR aes \
    ; aeadInit AEAD_GCM cipher@(CSTR aes) iv = Just $ AEAD cipher $ AEADState $ gcmInit aes iv \
    ; aeadInit AEAD_OCB cipher@(CSTR aes) iv = Just $ AEAD cipher $ AEADState $ ocbInit aes iv \
    ; aeadInit _        _                  _ = Nothing \
    }; \
instance BlockCipher128 CSTR where \
    { xtsEncrypt (CSTR aes1, CSTR aes2) = encryptXTS (aes1,aes2) \
    ; xtsDecrypt (CSTR aes1, CSTR aes2) = decryptXTS (aes1,aes2) \
    }; \
\
instance AEADModeImpl CSTR AESGCM where \
    { aeadStateAppendHeader (CSTR _) gcmState bs = gcmAppendAAD gcmState bs \
    ; aeadStateEncrypt (CSTR aes) gcmState input = gcmAppendEncrypt aes gcmState input \
    ; aeadStateDecrypt (CSTR aes) gcmState input = gcmAppendDecrypt aes gcmState input \
    ; aeadStateFinalize (CSTR aes) gcmState len  = gcmFinish aes gcmState len \
    }; \
\
{-instance AEADModeImpl CSTR AESOCB where \
    { aeadStateAppendHeader (CSTR aes) ocbState bs = ocbAppendAAD aes ocbState bs \
    ; aeadStateEncrypt (CSTR aes) ocbState input = ocbAppendEncrypt aes ocbState input \
    ; aeadStateDecrypt (CSTR aes) ocbState input = ocbAppendDecrypt aes ocbState input \
    ; aeadStateFinalize (CSTR aes) ocbState len  = ocbFinish aes ocbState len \
    }-}

--INSTANCE_BLOCKCIPHER(AES128)
--INSTANCE_BLOCKCIPHER(AES192)
--INSTANCE_BLOCKCIPHER(AES256)
