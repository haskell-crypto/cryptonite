{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}
module Main where

import              Gauge.Main
import              Crypto.Hash.Algorithms as Crypto
import "cryptonite" Crypto.KDF.PBKDF2 as Crypto
import "fastpbkdf2" Crypto.KDF.PBKDF2 as Fast
import              Data.ByteString as B

password :: ByteString
password = "password"

salt :: ByteString
salt = "salt"

runBench :: Int
         -> (ByteString -> ByteString -> ByteString)
         -> (ByteString -> ByteString -> ByteString)
         -> (ByteString -> ByteString -> ByteString)
         -> Benchmark
runBench iter cryptonite fastCryptonite fastBinding =
  bgroup (show iter)
    [ bench "cryptonite"      $ whnf (cryptonite     password) salt
    , bench "cryptonite-fast" $ whnf (fastCryptonite password) salt
    , bench "fastpbkdf2-hs"   $ whnf (fastBinding    password) salt
    ]

makeBench :: (Parameters -> ByteString -> ByteString -> ByteString)
          -> (Parameters -> ByteString -> ByteString -> ByteString)
          -> (ByteString -> ByteString -> Int -> Int -> ByteString)
          -> [Benchmark]
makeBench cryptonite fastCryptonite fastBinding =
    [ runBench 1
        (cryptonite (Parameters 1 32))
        (fastCryptonite (Parameters 1 32))
        (\p s -> fastBinding p s 1 32)
    , runBench 10000
        (cryptonite (Parameters 10000 32))
        (fastCryptonite (Parameters 10000 32))
        (\p s -> fastBinding p s 10000 32)
    ]

main :: IO ()
main = defaultMain
  [ bgroup "SHA1" $ makeBench
      (Crypto.generate (Crypto.prfHMAC Crypto.SHA1))
      (Crypto.fastPBKDF2_SHA1)
      (Fast.fastpbkdf2_hmac_sha1)
  , bgroup "SHA256" $ makeBench
      (Crypto.generate (Crypto.prfHMAC Crypto.SHA256))
      (Crypto.fastPBKDF2_SHA256)
      (Fast.fastpbkdf2_hmac_sha256)
  , bgroup "SHA512" $ makeBench
      (Crypto.generate (Crypto.prfHMAC Crypto.SHA512))
      (Crypto.fastPBKDF2_SHA512)
      (Fast.fastpbkdf2_hmac_sha512)
  ]
