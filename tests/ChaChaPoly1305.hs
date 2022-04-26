{-# LANGUAGE OverloadedStrings #-}
module ChaChaPoly1305 where

import qualified Crypto.Cipher.ChaChaPoly1305 as AEAD
import Imports
import Crypto.Error
import Poly1305 ()

import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)

plaintext, aad, key, iv, ivX, ciphertext, ciphertextX, tag, tagX, nonce1, nonce2, nonce3, nonce4, nonce5, nonce6, nonce7, nonce8, nonce9, nonce10 :: B.ByteString
plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
key = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
iv = "\x40\x41\x42\x43\x44\x45\x46\x47"
ivX = B.pack [0x40 .. 0x57]
constant = "\x07\x00\x00\x00"
ciphertext = "\xd3\x1a\x8d\x34\x64\x8e\x60\xdb\x7b\x86\xaf\xbc\x53\xef\x7e\xc2\xa4\xad\xed\x51\x29\x6e\x08\xfe\xa9\xe2\xb5\xa7\x36\xee\x62\xd6\x3d\xbe\xa4\x5e\x8c\xa9\x67\x12\x82\xfa\xfb\x69\xda\x92\x72\x8b\x1a\x71\xde\x0a\x9e\x06\x0b\x29\x05\xd6\xa5\xb6\x7e\xcd\x3b\x36\x92\xdd\xbd\x7f\x2d\x77\x8b\x8c\x98\x03\xae\xe3\x28\x09\x1b\x58\xfa\xb3\x24\xe4\xfa\xd6\x75\x94\x55\x85\x80\x8b\x48\x31\xd7\xbc\x3f\xf4\xde\xf0\x8e\x4b\x7a\x9d\xe5\x76\xd2\x65\x86\xce\xc6\x4b\x61\x16"
ciphertextX = "\xbd\x6d\x17\x9d\x3e\x83\xd4\x3b\x95\x76\x57\x94\x93\xc0\xe9\x39\x57\x2a\x17\x00\x25\x2b\xfa\xcc\xbe\xd2\x90\x2c\x21\x39\x6c\xbb\x73\x1c\x7f\x1b\x0b\x4a\xa6\x44\x0b\xf3\xa8\x2f\x4e\xda\x7e\x39\xae\x64\xc6\x70\x8c\x54\xc2\x16\xcb\x96\xb7\x2e\x12\x13\xb4\x52\x2f\x8c\x9b\xa4\x0d\xb5\xd9\x45\xb1\x1b\x69\xb9\x82\xc1\xbb\x9e\x3f\x3f\xac\x2b\xc3\x69\x48\x8f\x76\xb2\x38\x35\x65\xd3\xff\xf9\x21\xf9\x66\x4c\x97\x63\x7d\xa9\x76\x88\x12\xf6\x15\xc6\x8b\x13\xb5\x2e"
tag = "\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91"
tagX = "\xc0\x87\x59\x24\xc1\xc7\x98\x79\x47\xde\xaf\xd8\x78\x0a\xcf\x49"
nonce1  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce2  = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce3  = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce4  = "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
nonce5  = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
nonce6  = "\x00\x00\x00\x00\x00\x00\x00\x00"
nonce7  = "\x01\x00\x00\x00\x00\x00\x00\x00"
nonce8  = "\xff\x00\x00\x00\x00\x00\x00\x00"
nonce9  = "\x00\x01\x00\x00\x00\x00\x00\x00"
nonce10 = "\xff\xff\xff\xff\xff\xff\xff\xff"

tests = testGroup "ChaChaPoly1305"
    [ testCase "V1" runEncrypt
    , testCase "V1-decrypt" runDecrypt
    , testCase "V1-extended" runEncryptX
    , testCase "V1-extended-decrypt" runDecryptX
    , testCase "nonce increment" runNonceInc
    ]
  where runEncrypt =
            let ini                 = throwCryptoError $ AEAD.initialize key (throwCryptoError $ AEAD.nonce8 constant iv)
                afterAAD            = AEAD.finalizeAAD (AEAD.appendAAD aad ini)
                (out, afterEncrypt) = AEAD.encrypt plaintext afterAAD
                outtag              = AEAD.finalize afterEncrypt
             in propertyHoldCase [ eqTest "ciphertext" ciphertext out
                                 , eqTest "tag" tag (B.convert outtag)
                                 ]
        runEncryptX =
            let ini                 = throwCryptoError $ AEAD.initializeX key (throwCryptoError $ AEAD.nonce24 ivX)
                afterAAD            = AEAD.finalizeAAD (AEAD.appendAAD aad ini)
                (out, afterEncrypt) = AEAD.encrypt plaintext afterAAD
                outtag              = AEAD.finalize afterEncrypt
             in propertyHoldCase [ eqTest "ciphertext" ciphertextX out
                                 , eqTest "tag" tagX (B.convert outtag)
                                 ]

        runDecrypt =
            let ini                 = throwCryptoError $ AEAD.initialize key (throwCryptoError $ AEAD.nonce8 constant iv)
                afterAAD            = AEAD.finalizeAAD (AEAD.appendAAD aad ini)
                (out, afterDecrypt) = AEAD.decrypt ciphertext afterAAD
                outtag              = AEAD.finalize afterDecrypt
             in propertyHoldCase [ eqTest "plaintext" plaintext out
                                 , eqTest "tag" tag (B.convert outtag)
                                 ]

        runDecryptX =
            let ini                 = throwCryptoError $ AEAD.initializeX key (throwCryptoError $ AEAD.nonce24 ivX)
                afterAAD            = AEAD.finalizeAAD (AEAD.appendAAD aad ini)
                (out, afterDecrypt) = AEAD.decrypt ciphertextX afterAAD
                outtag              = AEAD.finalize afterDecrypt
             in propertyHoldCase [ eqTest "plaintext" plaintext out
                                 , eqTest "tag" tagX (B.convert outtag)
                                 ]

        runNonceInc =
            let n1  = throwCryptoError . AEAD.nonce12 $ nonce1
                n3  = throwCryptoError . AEAD.nonce12 $ nonce3
                n5  = throwCryptoError . AEAD.nonce12 $ nonce5
                n6  = throwCryptoError . AEAD.nonce8 constant $ nonce6
                n8  = throwCryptoError . AEAD.nonce8 constant $ nonce8
                n10 = throwCryptoError . AEAD.nonce8 constant $ nonce10
            in propertyHoldCase [ eqTest "nonce12a" nonce2 $ B.convert . AEAD.incrementNonce $ n1
                                , eqTest "nonce12b" nonce4 $ B.convert . AEAD.incrementNonce $ n3
                                , eqTest "nonce12c" nonce1 $ B.convert . AEAD.incrementNonce $ n5
                                , eqTest "nonce8a" (B.concat [constant, nonce7]) $ B.convert . AEAD.incrementNonce $ n6
                                , eqTest "nonce8b" (B.concat [constant, nonce9]) $ B.convert . AEAD.incrementNonce $ n8
                                , eqTest "nonce8c" (B.concat [constant, nonce6]) $ B.convert . AEAD.incrementNonce $ n10
                                ]
