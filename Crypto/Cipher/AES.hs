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

import Crypto.Error
import Crypto.Cipher.Types
import Crypto.Cipher.Types.Block
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

#define INSTANCE_BLOCKCIPHER(CSTR) \
instance BlockCipher CSTR where \
    { blockSize _ = 16 \
    ; ecbEncrypt (CSTR aes) = encryptECB aes \
    ; ecbDecrypt (CSTR aes) = decryptECB aes \
    ; cbcEncrypt (CSTR aes) (IV iv) = encryptCBC aes (IV iv) \
    ; cbcDecrypt (CSTR aes) (IV iv) = decryptCBC aes (IV iv) \
    ; ctrCombine (CSTR aes) (IV iv) = encryptCTR aes (IV iv) \
    ; aeadInit AEAD_GCM (CSTR aes) iv = CryptoPassed $ AEAD (gcmMode aes) (gcmInit aes iv) \
    ; aeadInit AEAD_OCB (CSTR aes) iv = CryptoPassed $ AEAD (ocbMode aes) (ocbInit aes iv) \
    ; aeadInit _        _          _  = CryptoFailed CryptoError_AEADModeNotSupported \
    }; \
instance BlockCipher128 CSTR where \
    { xtsEncrypt (CSTR aes1, CSTR aes2) (IV iv) = encryptXTS (aes1,aes2) (IV iv) \
    ; xtsDecrypt (CSTR aes1, CSTR aes2) (IV iv) = decryptXTS (aes1,aes2) (IV iv) \
    };

INSTANCE_BLOCKCIPHER(AES128)
INSTANCE_BLOCKCIPHER(AES192)
INSTANCE_BLOCKCIPHER(AES256)
