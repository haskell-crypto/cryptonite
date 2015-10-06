{-# LANGUAGE OverloadedStrings #-}
module KAT_Curve25519 ( tests ) where

import           Crypto.PubKey.Curve25519 (SecretKey, PublicKey, DhSecret)
import qualified Crypto.PubKey.Curve25519 as Curve25519
import           Data.ByteArray as B
import           Imports

goodSecret :: ByteString
goodSecret = "\x98\x6e\x4d\x65\x8f\xc7\x93\x7c\x11\x15\xa5\x16\xbd\xee\x26\xf3\x1a\x7c\xc8\x80\x6c\x54\xe5\x40\xb9\xf8\xfd\x46\x37\x34\x89\x60"

badSecret :: ByteString
badSecret = "\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"

dhTest :: Assertion
dhTest = do
    (ask, apk) <- Curve25519.generateKeypair
    (bsk, bpk) <- Curve25519.generateKeypair
    print $ (B.convert ask :: ByteString)
    assertBool "computed dh secrets do not match" $
      Curve25519.dh apk bsk == Curve25519.dh bpk ask

goodSecretTest :: Assertion
goodSecretTest = do
    case Curve25519.secretKey goodSecret of
      (Left _)  -> assertFailure "valid secret rejected"
      (Right _) -> return ()

badSecretTest :: Assertion
badSecretTest = do
    case Curve25519.secretKey badSecret of
      (Left _)  -> return ()
      (Right _) -> assertFailure "invalid secret accepted"

katTests :: [TestTree]
katTests = [ testCase "dh secret computation" dhTest
           , testCase "valid secret acceptance" goodSecretTest
           , testCase "invalid secret rejection" badSecretTest
           ]

tests = testGroup "Curve25519"
    [ testGroup "KATs" katTests
    ]
