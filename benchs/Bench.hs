{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Criterion.Main

import "cryptonite" Crypto.Hash
import "cryptonite" Crypto.Error
import "cryptonite" Crypto.Cipher.DES
import "cryptonite" Crypto.Cipher.Camellia
import "cryptonite" Crypto.Cipher.AES
import "cryptonite" Crypto.Cipher.Blowfish
import "cryptonite" Crypto.Cipher.Types

import "cryptonite" Crypto.Hash (SHA512(..))
import qualified "cryptonite" Crypto.KDF.PBKDF2 as PBKDF2

import Crypto.Internal.ByteArray (ByteArray)

import qualified Data.ByteString as B

benchHash =
    [ 
    ]

benchPBKDF2 =
    [ bgroup "64"
        [ bench "cryptonite-PBKDF2-100-64" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 64) 100
        , bench "cryptonite-PBKDF2-1000-64" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 64) 1000
        , bench "cryptonite-PBKDF2-10000-64" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 64) 10000
        ]
    , bgroup "128"
        [ bench "cryptonite-PBKDF2-100-128" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 128) 100
        , bench "cryptonite-PBKDF2-1000-128" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 128) 1000
        , bench "cryptonite-PBKDF2-10000-128" $ nf (PBKDF2.generate (PBKDF2.prfHMAC SHA512) . params 128) 10000
        ]
    ]
  where
        mypass = "password"
        mysalt = "salt"

        params n iter = PBKDF2.Parameters mypass mysalt iter n


benchBlockCipher =
    [ bgroup "ECB" benchECB
    , bgroup "CBC" benchCBC
    ]
  where 
        benchECB =
            [ bench "DES-input=1024" $ nf (run (undefined :: DES) cipherInit key8) input1024
            , bench "Blowfish128-input=1024" $ nf (run (undefined :: Blowfish128) cipherInit key16) input1024
            , bench "AES128-input=1024" $ nf (run (undefined :: AES128) cipherInit key16) input1024
            , bench "AES256-input=1024" $ nf (run (undefined :: AES256) cipherInit key32) input1024
            ]
          where run :: (ByteArray ba, ByteArray key, BlockCipher c)
                    => c -> (key -> CryptoFailable c) -> key -> ba -> ba
                run witness initF key input =
                    (ecbEncrypt (throwCryptoError (initF key))) input

        benchCBC =
            [ bench "DES-input=1024" $ nf (run (undefined :: DES) cipherInit key8 iv8) input1024
            , bench "Blowfish128-input=1024" $ nf (run (undefined :: Blowfish128) cipherInit key16 iv8) input1024
            , bench "AES128-input=1024" $ nf (run (undefined :: AES128) cipherInit key16 iv16) input1024
            , bench "AES256-input=1024" $ nf (run (undefined :: AES256) cipherInit key32 iv16) input1024
            ]
          where run :: (ByteArray ba, ByteArray key, BlockCipher c)
                    => c -> (key -> CryptoFailable c) -> key -> IV c -> ba -> ba
                run witness initF key iv input =
                    (cbcEncrypt (throwCryptoError (initF key))) iv input

        key8  = B.replicate 8 0
        key16 = B.replicate 16 0
        key32 = B.replicate 32 0
        input1024 = B.replicate 1024 0

        iv8 :: BlockCipher c => IV c
        iv8  = maybe (error "iv size 8") id  $ makeIV key8

        iv16 :: BlockCipher c => IV c
        iv16 = maybe (error "iv size 16") id $ makeIV key16

main = defaultMain
    [ bgroup "hash" benchHash
    , bgroup "block-cipher" benchBlockCipher
    , bgroup "pbkdf2" benchPBKDF2
    ]
