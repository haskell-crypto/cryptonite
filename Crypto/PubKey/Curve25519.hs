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
    , generateKeypair
    -- * Methods
    , dh
    , toPublic
    ) where

import           Data.Bits
import           Data.Word
import           Foreign.Ptr
import           Foreign.Storable
import           GHC.Ptr

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes, Bytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Random.Entropy

-- | A Curve25519 Secret key
newtype SecretKey = SecretKey ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | A Curve25519 public key
newtype PublicKey = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | A Curve25519 Diffie Hellman secret related to a
-- public key and a secret key.
newtype DhSecret = DhSecret ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | Try to build a public key from a bytearray
publicKey :: ByteArrayAccess bs => bs -> Either String PublicKey
publicKey bs
    | B.length bs == 32 = Right $ PublicKey $ B.copyAndFreeze bs (\_ -> return ())
    | otherwise               = Left "invalid public key size"

-- | Try to build a secret key from a bytearray
secretKey :: ByteArrayAccess bs => bs -> Either String SecretKey
secretKey bs
    | B.length bs == 32 = unsafeDoIO $
        withByteArray bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then (Right . SecretKey) <$> B.copy bs (\_ -> return ())
                else return $ Left "invalid secret key"
    | otherwise = Left "secret key invalid size"
  where
        --  e[0] &= 0xf8;
        --  e[31] &= 0x7f;
        --  e[31] |= 0x40;
        isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr inp = do
            b0  <- peekElemOff inp 0
            b31 <- peekElemOff inp 31

            return $ and [ not (testBit b0  0)
                         , not (testBit b0  1)
                         , not (testBit b0  2)
                         , not (testBit b31 7)
                         , testBit b31 6
                         ]

{-# NOINLINE secretKey #-}

-- | Generate a keypair
generateKeypair :: IO (SecretKey, PublicKey)
generateKeypair = do
    r <- getEntropy 32
    unsafeDoIO $
      return $ withByteArray r $ \inp -> do
        -- "A user can, for example, generate 32 uniform random bytes,
        -- clear bits 0,1,2 of the first byte, clear bit 7 of the last
        -- byte, and set bit 6 of the last byte."
        -- From: Public Key Cryptography - PKC 2006: 9th International
        -- Conference on Theory and Practice of Public-Key Cryptography,
        -- page 211
        b0  <- (.&.) 0xf8 <$> peekElemOff inp 0 :: IO Word8
        b31 <- (.&. 0x7f) . (.|. 0x40) <$> peekElemOff inp 31
        pokeElemOff inp 0  b0
        pokeElemOff inp 31 b31
    let sk = SecretKey r
    return (sk, toPublic sk)

{-# NOINLINE generateKeypair #-}

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
