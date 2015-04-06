-- |
-- Module      : Crypto.Cipher.Types.AEAD
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- AEAD cipher basic types
--
module Crypto.Cipher.Types.AEAD where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable
import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block

-- | Append associated data into the AEAD state
aeadAppendHeader :: BlockCipher a => AEAD a -> ByteString -> AEAD a
aeadAppendHeader (AEAD cipher (AEADState state)) bs =
    AEAD cipher $ AEADState (aeadStateAppendHeader cipher state bs)

-- | Encrypt input and append into the AEAD state
aeadEncrypt :: BlockCipher a => AEAD a -> ByteString -> (ByteString, AEAD a)
aeadEncrypt (AEAD cipher (AEADState state)) input = (output, AEAD cipher (AEADState nst))
  where (output, nst) = aeadStateEncrypt cipher state input

-- | Decrypt input and append into the AEAD state
aeadDecrypt :: BlockCipher a => AEAD a -> ByteString -> (ByteString, AEAD a)
aeadDecrypt (AEAD cipher (AEADState state)) input = (output, AEAD cipher (AEADState nst))
  where (output, nst) = aeadStateDecrypt cipher state input

-- | Finalize the AEAD state and create an authentification tag
aeadFinalize :: BlockCipher a => AEAD a -> Int -> AuthTag
aeadFinalize (AEAD cipher (AEADState state)) len =
    aeadStateFinalize cipher state len

-- | Simple AEAD encryption
aeadSimpleEncrypt :: BlockCipher a
                  => AEAD a        -- ^ A new AEAD Context
                  -> B.ByteString  -- ^ Optional Authentified Header
                  -> B.ByteString  -- ^ Optional Plaintext
                  -> Int           -- ^ Tag length
                  -> (AuthTag, B.ByteString) -- ^ Authentification tag and ciphertext
aeadSimpleEncrypt aeadIni header input taglen = (tag, output)
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadEncrypt aead input
        tag                 = aeadFinalize aeadFinal taglen

-- | Simple AEAD decryption
aeadSimpleDecrypt :: BlockCipher a
                  => AEAD a        -- ^ A new AEAD Context
                  -> B.ByteString  -- ^ Optional Authentified Header
                  -> B.ByteString  -- ^ Optional Plaintext
                  -> AuthTag       -- ^ Tag length
                  -> Maybe B.ByteString -- ^ Plaintext
aeadSimpleDecrypt aeadIni header input authTag
    | tag == authTag = Just output
    | otherwise      = Nothing
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadDecrypt aead input
        tag                 = aeadFinalize aeadFinal (byteableLength authTag)

