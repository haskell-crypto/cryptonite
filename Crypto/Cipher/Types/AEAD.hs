-- |
-- Module      : Crypto.Cipher.Types.AEAD
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- AEAD cipher basic types
--
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE Rank2Types #-}
module Crypto.Cipher.Types.AEAD where

import Crypto.Cipher.Types.Base
import Crypto.Internal.ByteArray
import Crypto.Internal.Imports

data AEADModeImpl st = AEADModeImpl
    { aeadImplAppendHeader :: forall ba . ByteArrayAccess ba => st -> ba -> st
    , aeadImplEncrypt      :: forall ba . ByteArray ba => st -> ba -> (ba, st)
    , aeadImplDecrypt      :: forall ba . ByteArray ba => st -> ba -> (ba, st)
    , aeadImplFinalize     :: st -> Int -> AuthTag
    }

-- | Authenticated Encryption with Associated Data algorithms
data AEAD cipher = forall st . AEAD
    { aeadModeImpl :: AEADModeImpl st
    , aeadState    :: st
    }

aeadAppendHeader :: ByteArrayAccess aad => AEAD cipher -> aad -> AEAD cipher
aeadAppendHeader (AEAD impl st) aad = AEAD impl $ (aeadImplAppendHeader impl) st aad

aeadEncrypt :: ByteArray ba => AEAD cipher -> ba -> (ba, AEAD cipher)
aeadEncrypt (AEAD impl st) ba = second (AEAD impl) $ (aeadImplEncrypt impl) st ba

aeadDecrypt :: ByteArray ba => AEAD cipher -> ba -> (ba, AEAD cipher)
aeadDecrypt (AEAD impl st) ba = second (AEAD impl) $ (aeadImplDecrypt impl) st ba

aeadFinalize :: AEAD cipher -> Int -> AuthTag
aeadFinalize (AEAD impl st) n = (aeadImplFinalize impl) st n

-- | Simple AEAD encryption
aeadSimpleEncrypt :: (ByteArrayAccess aad, ByteArray ba)
                  => AEAD a        -- ^ A new AEAD Context
                  -> aad           -- ^ Optional Authentified Header
                  -> ba            -- ^ Optional Plaintext
                  -> Int           -- ^ Tag length
                  -> (AuthTag, ba) -- ^ Authentification tag and ciphertext
aeadSimpleEncrypt aeadIni header input taglen = (tag, output)
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadEncrypt aead input
        tag                 = aeadFinalize aeadFinal taglen

-- | Simple AEAD decryption
aeadSimpleDecrypt :: (ByteArrayAccess aad, ByteArray ba)
                  => AEAD a        -- ^ A new AEAD Context
                  -> aad           -- ^ Optional Authentified Header
                  -> ba            -- ^ Optional Plaintext
                  -> AuthTag       -- ^ Tag length
                  -> Maybe ba      -- ^ Plaintext
aeadSimpleDecrypt aeadIni header input authTag
    | tag == authTag = Just output
    | otherwise      = Nothing
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadDecrypt aead input
        tag                 = aeadFinalize aeadFinal (byteArrayLength authTag)

