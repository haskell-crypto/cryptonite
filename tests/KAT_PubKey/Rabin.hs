{-# LANGUAGE OverloadedStrings #-}
module KAT_PubKey.Rabin (rabinTests) where

import           Imports
import           Crypto.Hash
import qualified Crypto.PubKey.Rabin.Basic as Basic
import qualified Crypto.PubKey.Rabin.Modified as ModRabin
import qualified Crypto.PubKey.Rabin.RW as RW

data VectorRabin = VectorRabin
    { msg  :: ByteString
    , size :: Int
    }

vectors =
    [ VectorRabin
        { msg = "\xd4\x36\xe9\x95\x69\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"
        , size = 32
        }
    , VectorRabin
        { msg = "\x52\xe6\x50\xd9\x8e\x7f\x2a\x04\x8b\x4f\x86\x85\x21\x53\xb9\x7e\x01\xdd\x31\x6f\x34\x6a\x19\xf6\x7a\x85"
        , size = 64
        }
    , VectorRabin
        { msg = "\x66\x28\x19\x4e\x12\x07\x3d\xb0\x3b\xa9\x4c\xda\x9e\xf9\x53\x23\x97\xd5\x0d\xba\x79\xb9\x87\x00\x4a\xfe\xfe\x34"
        , size = 128
        }        
    ]

doBasicEncryptionTest (i, vector) = testCase (show i) (do
    let message = msg vector
    (pubKey, privKey) <- Basic.generate (size vector)
    let cipherText = Basic.encrypt pubKey message
        actual = case cipherText of
                    Left _  -> False
                    Right c -> let (p, p', p'', p''') = Basic.decrypt privKey c
                                in elem message [p, p', p'', p''']
    (True @=? actual))

doBasicSignatureTest (i, vector) = testCase (show i) (do
    let message = msg vector
    (pubKey, privKey) <- Basic.generate (size vector)
    signature <- Basic.sign privKey SHA1 message
    let actual = case signature of
                    Left _  -> False
                    Right s -> Basic.verify pubKey SHA1 message s
    (True @=? actual))

doModifiedSignatureTest (i, vector) = testCase (show i) (do
    let message = msg vector
    (pubKey, privKey) <- ModRabin.generate (size vector)
    let signature = ModRabin.sign privKey SHA1 message
        actual = case signature of
                    Left _  -> False
                    Right s -> ModRabin.verify pubKey SHA1 message s
    (True @=? actual))

doRwEncryptionTest (i, vector) = testCase (show i) (do
    let message = msg vector
    (pubKey, privKey) <- RW.generate (size vector)
    let cipherText = RW.encrypt pubKey message
        actual = case cipherText of
                    Left _  -> False
                    Right c -> let p = RW.decrypt privKey c
                                in message == p
    (True @=? actual))

doRwSignatureTest (i, vector) = testCase (show i) (do
    let message = msg vector
    (pubKey, privKey) <- RW.generate (size vector)
    let signature = RW.sign privKey SHA1 message
        actual = case signature of
                    Left _  -> False
                    Right s -> RW.verify pubKey SHA1 message s
    (True @=? actual))

rabinTests = testGroup "Rabin"
    [ testGroup "Basic"
        [ testGroup "encryption" $ map doBasicEncryptionTest (zip [katZero..] vectors)
        , testGroup "signature" $ map doBasicSignatureTest (zip [katZero..] vectors)
        ]
    , testGroup "Modified"
        [ testGroup "signature" $ map doModifiedSignatureTest (zip [katZero..] vectors)
        ]
    , testGroup "RW"
        [ testGroup "encryption" $ map doRwEncryptionTest (zip [katZero..] vectors)
        , testGroup "signature" $ map doRwSignatureTest (zip [katZero..] vectors)
        ]
    ]
