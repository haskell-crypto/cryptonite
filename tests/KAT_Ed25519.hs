{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
module KAT_Ed25519 ( tests ) where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import           Imports

data Vec = Vec
    { vecSec :: ByteString
    , vecPub :: ByteString
    , vecMsg :: ByteString
    , vecSig :: ByteString
    } deriving (Show,Eq)

vec1 = Vec
    { vecSec = "\x4c\xcd\x08\x9b\x28\xff\x96\xda\x9d\xb6\xc3\x46\xec\x11\x4e\x0f\x5b\x8a\x31\x9f\x35\xab\xa6\x24\xda\x8c\xf6\xed\x4f\xb8\xa6\xfb"
    , vecPub = "\x3d\x40\x17\xc3\xe8\x43\x89\x5a\x92\xb7\x0a\xa7\x4d\x1b\x7e\xbc\x9c\x98\x2c\xcf\x2e\xc4\x96\x8c\xc0\xcd\x55\xf1\x2a\xf4\x66\x0c"
    , vecMsg = "\x72"
    , vecSig = "\x92\xa0\x09\xa9\xf0\xd4\xca\xb8\x72\x0e\x82\x0b\x5f\x64\x25\x40\xa2\xb2\x7b\x54\x16\x50\x3f\x8f\xb3\x76\x22\x23\xeb\xdb\x69\xda\x08\x5a\xc1\xe4\x3e\x15\x99\x6e\x45\x8f\x36\x13\xd0\xf1\x1d\x8c\x38\x7b\x2e\xae\xb4\x30\x2a\xee\xb0\x0d\x29\x16\x12\xbb\x0c\x00"
    }

testVec :: String -> Vec -> [TestTree]
testVec s vec =
    [ testCase (s ++ " gen publickey") (pub @=? Ed25519.toPublic sec)
    , testCase (s ++ " gen secretkey") (Ed25519.generateSecretKey *> pure ())
    , testCase (s ++ " gen signature") (sig @=? Ed25519.sign sec pub (vecMsg vec))
    ]
  where
        !sig = throwCryptoError $ Ed25519.signature (vecSig vec)
        !pub = throwCryptoError $ Ed25519.publicKey (vecPub vec)
        !sec = throwCryptoError $ Ed25519.secretKey (vecSec vec)

katTests :: [TestTree]
katTests = testVec "vec 1" vec1

tests = testGroup "Ed25519"
    [ testGroup "KATs" katTests
    ]
