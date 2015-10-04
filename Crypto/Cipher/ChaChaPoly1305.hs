{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Cipher.ChaChaPoly1305
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- A simple AEAD scheme using ChaCha20 and Poly1305.
-- 
-- See RFC7539.
--
module Crypto.Cipher.ChaChaPoly1305
    ( State
    , Nonce
    , nonce12
    , nonce8
    , incrementNonce
    , initialize
    , appendAAD
    , finalizeAAD
    , encrypt
    , decrypt
    , finalize
    ) where

import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray, Bytes, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Imports
import           Crypto.Error
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.MAC.Poly1305  as Poly1305
import           Data.Memory.Endian
import qualified Data.ByteArray.Pack as P
import           Foreign.Ptr
import           Foreign.C.Types

data State = State !ChaCha.State
                   !Poly1305.State
                   !Word64 -- AAD length
                   !Word64 -- ciphertext length

newtype Nonce = Nonce Bytes
    deriving (ByteArrayAccess)

-- Based on the following pseudo code:
--
-- chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
--     nonce = constant | iv
--     otk = poly1305_key_gen(key, nonce)
--     ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
--     mac_data = aad | pad16(aad)
--     mac_data |= ciphertext | pad16(ciphertext)
--     mac_data |= num_to_4_le_bytes(aad.length)
--     mac_data |= num_to_4_le_bytes(ciphertext.length)
--     tag = poly1305_mac(mac_data, otk)
--     return (ciphertext, tag)

pad16 :: Word64 -> Bytes
pad16 n
    | modLen == 0 = B.empty
    | otherwise   = B.replicate (16 - modLen) 0
  where
    modLen = fromIntegral (n `mod` 16)

-- | Nonce smart constructor 12 bytes IV, nonce constructor
nonce12 :: ByteArrayAccess iv => iv -> CryptoFailable Nonce
nonce12 iv
    | B.length iv /= 12 = CryptoFailed  $ CryptoError_IvSizeInvalid
    | otherwise         = CryptoPassed $ Nonce (B.convert iv)

-- | 8 bytes IV, nonce constructor
nonce8 :: ByteArrayAccess ba
       => ba -- ^ 4 bytes constant 
       -> ba -- ^ 8 bytes IV
       -> CryptoFailable Nonce
nonce8 constant iv
    | B.length constant /= 4 = CryptoFailed $ CryptoError_IvSizeInvalid
    | B.length iv       /= 8 = CryptoFailed $ CryptoError_IvSizeInvalid
    | otherwise              = CryptoPassed $ Nonce $ B.concat [constant, iv]

-- | Increment a nonce
incrementNonce :: Nonce -> Nonce
incrementNonce (Nonce n) =
    Nonce $ B.copyAndFreeze n $ \out -> do
      cryptonite_util_increment_array out $ fromIntegral $ B.length n

initialize :: ByteArrayAccess key
           => key -> Nonce -> CryptoFailable State
initialize key (Nonce nonce)
    | B.length key /= 32 = CryptoFailed $ CryptoError_KeySizeInvalid
    | otherwise          = CryptoPassed $ State encState polyState 0 0
  where
    rootState           = ChaCha.initialize 20 key nonce
    (polyKey, encState) = ChaCha.generate rootState 64
    polyState           = throwCryptoError $ Poly1305.initialize (B.take 32 polyKey :: ScrubbedBytes)

appendAAD :: ByteArrayAccess ba => ba -> State -> State
appendAAD ba (State encState macState aadLength plainLength) =
    State encState newMacState newLength plainLength
  where
    newMacState = Poly1305.update macState ba
    newLength   = aadLength + fromIntegral (B.length ba)

finalizeAAD :: State -> State
finalizeAAD (State encState macState aadLength plainLength) =
    State encState newMacState aadLength plainLength
  where
    newMacState = Poly1305.update macState $ pad16 aadLength

encrypt :: ByteArray ba => ba -> State -> (ba, State)
encrypt input (State encState macState aadLength plainLength) =
    (output, State newEncState newMacState aadLength newPlainLength)
  where
    (output, newEncState) = ChaCha.combine encState input
    newMacState           = Poly1305.update macState output
    newPlainLength        = plainLength + fromIntegral (B.length input)

decrypt :: ByteArray ba => ba -> State -> (ba, State)
decrypt input (State encState macState aadLength plainLength) =
    (output, State newEncState newMacState aadLength newPlainLength)
  where
    (output, newEncState) = ChaCha.combine encState input
    newMacState           = Poly1305.update macState input
    newPlainLength        = plainLength + fromIntegral (B.length input)

finalize :: State -> Poly1305.Auth
finalize (State _ macState aadLength plainLength) =
    Poly1305.finalize $ Poly1305.updates macState
        [ pad16 plainLength
        , either (error "finalize: internal error") id $ P.fill 16 (P.putStorable (toLE aadLength) >> P.putStorable (toLE plainLength))
        ]

foreign import ccall "cryptonite_util_increment_array"
    cryptonite_util_increment_array :: Ptr Word8 -> CSize -> IO ()
