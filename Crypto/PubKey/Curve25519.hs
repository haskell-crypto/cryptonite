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
    -- * methods
    , dh
    , toPublic
    , toSecret
    ) where

import           Control.Applicative
import           Data.Bits
import           Data.Byteable
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import           Data.SecureMem
import           Data.Word
import           Foreign.Ptr
import           Foreign.Storable

import           Crypto.Internal.Compat

--  e[0] &= 0xf8;
--  e[31] &= 0x7f;
--  e[31] |= 40;
newtype SecretKey = SecretKey SecureMem
    deriving (Show,Eq,Byteable)

newtype PublicKey = PublicKey ByteString
    deriving (Show,Eq,Byteable)

newtype DhSecret = DhSecret ByteString
    deriving (Show,Eq,Byteable)

basePoint :: PublicKey
basePoint = PublicKey "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

dh :: PublicKey -> SecretKey -> DhSecret
dh (PublicKey pub) (SecretKey sec) = DhSecret <$>
    B.unsafeCreate 32    $ \result ->
    withSecureMemPtr sec $ \psec   ->
    withBytePtr pub      $ \ppub   ->
        ccryptonite_curve25519 result psec ppub

toPublic :: SecretKey -> PublicKey
toPublic (SecretKey sec) = PublicKey <$>
    B.unsafeCreate 32     $ \result ->
    withSecureMemPtr sec  $ \psec   ->
    withBytePtr basePoint $ \pbase   ->
        ccryptonite_curve25519 result psec pbase

toSecret :: Byteable bs => bs -> Either String SecretKey
toSecret bs
    | byteableLength bs == 32 = unsafeDoIO $ do
        withBytePtr bs $ \inp -> do
            valid <- isValidPtr inp
            if valid
                then Right . SecretKey <$> createSecureMem 32 (\sec -> B.memcpy sec inp 32)
                else return $ Left "invalid secret key"
    | otherwise               = Left "secret key invalid size"

  where isValidPtr :: Ptr Word8 -> IO Bool
        isValidPtr inp = do
            b0  <- peekElemOff inp 0
            b31 <- peekElemOff inp 31
            return $ and [ testBit b0  0 == False
                         , testBit b0  1 == False  
                         , testBit b0  2 == False
                         , testBit b31 7 == False
                         , testBit b31 6 == True
                         ]

--generateSecret :: IO ByteString

foreign import ccall "cryptonite_curve25519_donna"
    ccryptonite_curve25519 :: Ptr Word8 -- ^ public
                           -> Ptr Word8 -- ^ secret
                           -> Ptr Word8 -- ^ basepoint
                           -> IO ()
