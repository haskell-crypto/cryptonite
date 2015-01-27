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
{-# LANGUAGE OverloadedStrings #-}
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

import           Control.Applicative
import           Data.Bits
import           Data.Byteable
import           Data.ByteString (ByteString)
import           Data.ByteString.Char8 ()
import qualified Data.ByteString.Internal as B
import           Data.SecureMem
import           Data.Word
import           Foreign.Ptr
import           Foreign.Storable

import           Crypto.Internal.Compat

-- | A Curve25519 Secret key
newtype SecretKey = SecretKey SecureMem
    deriving (Show,Eq,Byteable)

-- | A Curve25519 public key
newtype PublicKey = PublicKey ByteString
    deriving (Show,Eq,Byteable)

-- | A Curve25519 Diffie Hellman secret related to a
-- public key and a secret key.
newtype DhSecret = DhSecret SecureMem
    deriving (Show,Eq,Byteable)

-- | Try to build a public key from a bytearray
publicKey :: Byteable bs => bs -> Either String PublicKey
publicKey bs
    | byteableLength bs == 32 = Right $ PublicKey $ toBytes bs
    | otherwise               = Left "invalid public key size"

-- | Try to build a secret key from a bytearray
secretKey :: Byteable bs => bs -> Either String SecretKey
secretKey bs
    | byteableLength bs == 32 = unsafeDoIO $ do
        withBytePtr bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then Right . SecretKey <$> createSecureMem 32 (\sec -> B.memcpy sec inp 32)
                else return $ Left "invalid secret key"
    | otherwise = Left "secret key invalid size"
  where
        --  e[0] &= 0xf8;
        --  e[31] &= 0x7f;
        --  e[31] |= 40;
        isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr inp = do
            b0  <- peekElemOff inp 0
            b31 <- peekElemOff inp 31
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
dhSecret :: Byteable b => b -> Either String DhSecret
dhSecret bs
    | byteableLength bs == 32 = Right $ DhSecret $ secureMemFromByteable bs
    | otherwise               = Left "invalid dh secret size"

basePoint :: PublicKey
basePoint = PublicKey "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

-- | Compute the Diffie Hellman secret from a public key and a secret key
dh :: PublicKey -> SecretKey -> DhSecret
dh (PublicKey pub) (SecretKey sec) = DhSecret <$> unsafeDoIO $
    createSecureMem 32   $ \result ->
    withSecureMemPtr sec $ \psec   ->
    withBytePtr pub      $ \ppub   ->
        ccryptonite_curve25519 result psec ppub
{-# NOINLINE dh #-}

-- | Create a public key from a secret key
toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    B.unsafeCreate 32     $ \result ->
    withSecureMemPtr sec  $ \psec   ->
    withBytePtr basePoint $ \pbase   ->
        ccryptonite_curve25519 result psec pbase
{-# NOINLINE toPublic #-}

foreign import ccall "cryptonite_curve25519_donna"
    ccryptonite_curve25519 :: Ptr Word8 -- ^ public
                           -> Ptr Word8 -- ^ secret
                           -> Ptr Word8 -- ^ basepoint
                           -> IO ()
