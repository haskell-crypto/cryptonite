-- |
-- Module      : Crypto.PubKey.Ed448
-- License     : BSD-style
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed448 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
module Crypto.PubKey.Ed448
    ( SecretKey
    , PublicKey
    , DhSecret
    -- * Smart constructors
    , dhSecret
    , publicKey
    , secretKey
    -- * methods
    , dh
    , toPublic
    ) where

import           Data.Word
import           Foreign.Ptr
import           GHC.Ptr

import           Crypto.Error
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes, Bytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B

-- | A Ed448 Secret key
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | A Ed448 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | A Ed448 Diffie Hellman secret related to a
-- public key and a secret key.
newtype DhSecret = DhSecret ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess bs => bs -> CryptoFailable PublicKey
publicKey bs
    | B.length bs == x448_bytes = CryptoPassed $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise                 = CryptoFailed CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess bs => bs -> CryptoFailable SecretKey
secretKey bs
    | B.length bs == x448_bytes = unsafeDoIO $
        withByteArray bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then (CryptoPassed . SecretKey) <$> B.copy bs (\_ -> return ())
                else return $ CryptoFailed CryptoError_SecretKeyStructureInvalid
    | otherwise = CryptoFailed CryptoError_SecretKeySizeInvalid
  where
        isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr _ =
            return True
{-# NOINLINE secretKey #-}

-- | Create a DhSecret from a bytearray object
dhSecret :: ByteArrayAccess b => b -> CryptoFailable DhSecret
dhSecret bs
    | B.length bs == x448_bytes = CryptoPassed $ DhSecret $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise                 = CryptoFailed CryptoError_SharedSecretSizeInvalid

-- | Compute the Diffie Hellman secret from a public key and a secret key
dh :: PublicKey -> SecretKey -> DhSecret
dh (PublicKey pub) (SecretKey sec) = DhSecret <$>
    B.allocAndFreeze x448_bytes $ \result ->
    withByteArray sec           $ \psec   ->
    withByteArray pub           $ \ppub   ->
        ccryptonite_ed448 result psec ppub
{-# NOINLINE dh #-}

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    B.allocAndFreeze x448_bytes     $ \result ->
    withByteArray sec               $ \psec   ->
        ccryptonite_ed448 result psec basePoint
  where
        basePoint = Ptr "\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#
{-# NOINLINE toPublic #-}

x448_bytes :: Int
x448_bytes = 448 `quot` 8

foreign import ccall "cryptonite_x448"
    ccryptonite_ed448 :: Ptr Word8 -- ^ public
                      -> Ptr Word8 -- ^ secret
                      -> Ptr Word8 -- ^ basepoint
                      -> IO ()
