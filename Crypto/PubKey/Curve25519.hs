-- |
-- Module      : Crypto.PubKey.Curve25519
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Curve25519 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
module Crypto.PubKey.Curve25519
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

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, SecureBytes, Bytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B

-- | A Curve25519 Secret key
newtype SecretKey = SecretKey SecureBytes
    deriving (Show,Eq,ByteArrayAccess)

-- | A Curve25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess)

-- | A Curve25519 Diffie Hellman secret related to a
-- public key and a secret key.
newtype DhSecret = DhSecret SecureBytes
    deriving (Show,Eq,ByteArrayAccess)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess bs => bs -> Either String PublicKey
publicKey bs
    | B.length bs == 32 = Right $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise               = Left "invalid public key size"

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess bs => bs -> Either String SecretKey
secretKey bs
    | B.length bs == 32 = unsafeDoIO $ do
        withByteArray bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then Right . SecretKey <$> B.copy bs (\_ -> return ())
                else return $ Left "invalid secret key"
    | otherwise = Left "secret key invalid size"
  where
        --  e[0] &= 0xf8;
        --  e[31] &= 0x7f;
        --  e[31] |= 40;
        isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr _ = do
            --b0  <- peekElemOff inp 0
            --b31 <- peekElemOff inp 31
            return True
{-
            return $ and [ testBit b0  0 == False
                         , testBit b0  1 == False
                         , testBit b0  2 == False
                         , testBit b31 7 == False
                         , testBit b31 6 == True
                         ]
-}
{-# NOINLINE secretKey #-}

-- | Create a DhSecret from a bytearray object
dhSecret :: ByteArrayAccess b => b -> Either String DhSecret
dhSecret bs
    | B.length bs == 32 = Right $ DhSecret $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise         = Left "invalid dh secret size"

-- | Compute the Diffie Hellman secret from a public key and a secret key
dh :: PublicKey -> SecretKey -> DhSecret
dh (PublicKey pub) (SecretKey sec) = DhSecret <$>
    B.allocAndFreeze 32        $ \result ->
    withByteArray sec          $ \psec   ->
    withByteArray pub          $ \ppub   ->
        ccryptonite_curve25519 result psec ppub
{-# NOINLINE dh #-}

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    B.allocAndFreeze 32     $ \result ->
    withByteArray sec       $ \psec   ->
        ccryptonite_curve25519 result psec basePoint
  where
        basePoint = Ptr "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#
{-# NOINLINE toPublic #-}

foreign import ccall "cryptonite_curve25519_donna"
    ccryptonite_curve25519 :: Ptr Word8 -- ^ public
                           -> Ptr Word8 -- ^ secret
                           -> Ptr Word8 -- ^ basepoint
                           -> IO ()
