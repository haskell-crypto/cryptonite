-- |
-- Module      : Crypto.PubKey.Ed25519
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed25519 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
module Crypto.PubKey.Ed25519
    ( SecretKey
    , PublicKey
    , Signature
    -- * Smart constructors
    , signature
    , publicKey
    , secretKey
    -- * methods
    , toPublic
    , sign
    , verify
    ) where

import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.Memory
import           Crypto.Internal.ByteArray
import           Crypto.Error

-- | An Ed25519 Secret key
newtype SecretKey = SecretKey SecureBytes
    deriving (Eq,ByteArrayAccess)

-- | An Ed25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess)

-- | An Ed25519 signature
newtype Signature = Signature Bytes
    deriving (Show,Eq,ByteArrayAccess)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess ba => ba -> CryptoFailable PublicKey
publicKey bs
    | byteArrayLength bs == publicKeySize =
        CryptoPassed $ PublicKey $ byteArrayCopyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed $ CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess ba => ba -> CryptoFailable SecretKey
secretKey bs
    | byteArrayLength bs == secretKeySize = unsafeDoIO $ do
        withByteArray bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then CryptoPassed . SecretKey <$> byteArrayCopy bs (\_ -> return ())
                else return $ CryptoFailed CryptoError_SecretKeyStructureInvalid
    | otherwise = CryptoFailed CryptoError_SecretKeyStructureInvalid
  where
        isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr _ = do
            return True
{-# NOINLINE secretKey #-}

-- | Try to build a signature from a bytearray
signature :: ByteArrayAccess ba => ba -> CryptoFailable Signature
signature bs
    | byteArrayLength bs == signatureSize =
        CryptoPassed $ Signature $ byteArrayCopyAndFreeze bs (\_ -> return ())
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    byteArrayAllocAndFreeze publicKeySize $ \result ->
    withByteArray sec                     $ \psec   ->
        ccryptonite_ed25519_publickey psec result
{-# NOINLINE toPublic #-}

-- | Sign a message using the key pair
sign :: ByteArrayAccess ba => SecretKey -> PublicKey -> ba -> Signature
sign secret public message =
    Signature $ byteArrayAllocAndFreeze signatureSize $ \sig ->
        withByteArray secret  $ \sec ->
        withByteArray public  $ \pub ->
        withByteArray message $ \msg ->
             ccryptonite_ed25519_sign msg (fromIntegral msgLen) sec pub sig
  where
    !msgLen = byteArrayLength message

-- | Verify a message
verify :: ByteArrayAccess ba => PublicKey -> ba -> Signature -> Bool
verify public message signatureVal = unsafeDoIO $
    withByteArray signatureVal $ \sig ->
    withByteArray public       $ \pub ->
    withByteArray message      $ \msg -> do
      r <- ccryptonite_ed25519_sign_open msg (fromIntegral msgLen) pub sig
      return (r == 0)
  where
    !msgLen = byteArrayLength message

publicKeySize :: Int
publicKeySize = 32

secretKeySize :: Int
secretKeySize = 32

signatureSize :: Int
signatureSize = 64

foreign import ccall "cryptonite_ed25519_publickey"
    ccryptonite_ed25519_publickey :: Ptr SecretKey -- secret key
                                  -> Ptr PublicKey -- public key
                                  -> IO ()

foreign import ccall "cryptonite_ed25519_sign_open"
    ccryptonite_ed25519_sign_open :: Ptr Word8     -- message
                                  -> CSize         -- message len
                                  -> Ptr PublicKey -- public
                                  -> Ptr Signature -- signature
                                  -> IO CInt

foreign import ccall "cryptonite_ed25519_sign"
    ccryptonite_ed25519_sign :: Ptr Word8     -- message
                             -> CSize         -- message len
                             -> Ptr SecretKey -- secret
                             -> Ptr PublicKey -- public
                             -> Ptr Signature -- signature
                             -> IO ()
