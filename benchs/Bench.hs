{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
module Main where

import Criterion.Main

import           Crypto.Cipher.AES
import           Crypto.Cipher.Blowfish
import           Crypto.Cipher.CAST5
import qualified Crypto.Cipher.ChaChaPoly1305 as CP
import           Crypto.Cipher.DES
import           Crypto.Cipher.Twofish
import           Crypto.Cipher.Types
import           Crypto.ECC
import           Crypto.Error
import           Crypto.Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import           Crypto.Random

import           Control.DeepSeq (NFData)
import           Data.ByteArray (ByteArray, Bytes)
import qualified Data.ByteString as B

import Number.F2m

data HashAlg = forall alg . HashAlgorithm alg => HashAlg alg

benchHash =
    [ env oneKB $ \b -> bgroup "1KB" $ map (doHashBench b) hashAlgs
    , env oneMB $ \b -> bgroup "1MB" $ map (doHashBench b) hashAlgs
    ]
  where
    doHashBench b (name, HashAlg alg) = bench name $ nf (hashWith alg) b

    oneKB :: IO Bytes
    oneKB = getRandomBytes 1024

    oneMB :: IO Bytes
    oneMB = getRandomBytes $ 1024 * 1024

    hashAlgs =
        [ ("MD2", HashAlg MD2)
        , ("MD4", HashAlg MD4)
        , ("MD5", HashAlg MD5)
        , ("SHA1", HashAlg SHA1)
        , ("SHA224", HashAlg SHA224)
        , ("SHA256", HashAlg SHA256)
        , ("SHA384", HashAlg SHA384)
        , ("SHA512", HashAlg SHA512)
        , ("SHA512t_224", HashAlg SHA512t_224)
        , ("SHA512t_256", HashAlg SHA512t_256)
        , ("RIPEMD160", HashAlg RIPEMD160)
        , ("Tiger", HashAlg Tiger)
        --, ("Skein256-160", HashAlg Skein256_160)
        , ("Skein256-256", HashAlg Skein256_256)
        --, ("Skein512-160", HashAlg Skein512_160)
        , ("Skein512-384", HashAlg Skein512_384)
        , ("Skein512-512", HashAlg Skein512_512)
        --, ("Skein512-896", HashAlg Skein512_896)
        , ("Whirlpool", HashAlg Whirlpool)
        , ("Keccak-224", HashAlg Keccak_224)
        , ("Keccak-256", HashAlg Keccak_256)
        , ("Keccak-384", HashAlg Keccak_384)
        , ("Keccak-512", HashAlg Keccak_512)
        , ("SHA3-224", HashAlg SHA3_224)
        , ("SHA3-256", HashAlg SHA3_256)
        , ("SHA3-384", HashAlg SHA3_384)
        , ("SHA3-512", HashAlg SHA3_512)
        , ("Blake2b-160", HashAlg Blake2b_160)
        , ("Blake2b-224", HashAlg Blake2b_224)
        , ("Blake2b-256", HashAlg Blake2b_256)
        , ("Blake2b-384", HashAlg Blake2b_384)
        , ("Blake2b-512", HashAlg Blake2b_512)
        , ("Blake2s-160", HashAlg Blake2s_160)
        , ("Blake2s-224", HashAlg Blake2s_224)
        , ("Blake2s-256", HashAlg Blake2s_256)
        ]

benchPBKDF2 =
    [ bgroup "64"
        [ bench "cryptonite-PBKDF2-100-64" $ nf (pbkdf2 64) 100
        , bench "cryptonite-PBKDF2-1000-64" $ nf (pbkdf2 64) 1000
        , bench "cryptonite-PBKDF2-10000-64" $ nf (pbkdf2 64) 10000
        ]
    , bgroup "128"
        [ bench "cryptonite-PBKDF2-100-128" $ nf (pbkdf2 128) 100
        , bench "cryptonite-PBKDF2-1000-128" $ nf (pbkdf2 128) 1000
        , bench "cryptonite-PBKDF2-10000-128" $ nf (pbkdf2 128) 10000
        ]
    ]
  where
        pbkdf2 :: Int -> Int -> B.ByteString
        pbkdf2 n iter = PBKDF2.generate (PBKDF2.prfHMAC SHA512) (params n iter) mypass mysalt

        mypass, mysalt :: B.ByteString
        mypass = "password"
        mysalt = "salt"

        params n iter = PBKDF2.Parameters iter n


benchBlockCipher =
    [ bgroup "ECB" benchECB
    , bgroup "CBC" benchCBC
    ]
  where 
        benchECB =
            [ bench "DES-input=1024" $ nf (run (undefined :: DES) cipherInit key8) input1024
            , bench "Blowfish128-input=1024" $ nf (run (undefined :: Blowfish128) cipherInit key16) input1024
            , bench "Twofish128-input=1024" $ nf (run (undefined :: Twofish128) cipherInit key16) input1024
            , bench "CAST5-128-input=1024" $ nf (run (undefined :: CAST5) cipherInit key16) input1024
            , bench "AES128-input=1024" $ nf (run (undefined :: AES128) cipherInit key16) input1024
            , bench "AES256-input=1024" $ nf (run (undefined :: AES256) cipherInit key32) input1024
            ]
          where run :: (ByteArray ba, ByteArray key, BlockCipher c)
                    => c -> (key -> CryptoFailable c) -> key -> ba -> ba
                run _witness initF key input =
                    (ecbEncrypt (throwCryptoError (initF key))) input

        benchCBC =
            [ bench "DES-input=1024" $ nf (run (undefined :: DES) cipherInit key8 iv8) input1024
            , bench "Blowfish128-input=1024" $ nf (run (undefined :: Blowfish128) cipherInit key16 iv8) input1024
            , bench "Twofish128-input=1024" $ nf (run (undefined :: Twofish128) cipherInit key16 iv16) input1024
            , bench "CAST5-128-input=1024" $ nf (run (undefined :: CAST5) cipherInit key16 iv8) input1024
            , bench "AES128-input=1024" $ nf (run (undefined :: AES128) cipherInit key16 iv16) input1024
            , bench "AES256-input=1024" $ nf (run (undefined :: AES256) cipherInit key32 iv16) input1024
            ]
          where run :: (ByteArray ba, ByteArray key, BlockCipher c)
                    => c -> (key -> CryptoFailable c) -> key -> IV c -> ba -> ba
                run _witness initF key iv input =
                    (cbcEncrypt (throwCryptoError (initF key))) iv input

        key8  = B.replicate 8 0
        key16 = B.replicate 16 0
        key32 = B.replicate 32 0
        input1024 = B.replicate 1024 0

        iv8 :: BlockCipher c => IV c
        iv8  = maybe (error "iv size 8") id  $ makeIV key8

        iv16 :: BlockCipher c => IV c
        iv16 = maybe (error "iv size 16") id $ makeIV key16

benchAE =
    [ bench "ChaChaPoly1305" $ nf (run key32) (input64, input1024)
    ]
  where run k (ini, plain) =
            let iniState            = throwCryptoError $ CP.initialize k (throwCryptoError $ CP.nonce12 nonce12)
                afterAAD            = CP.finalizeAAD (CP.appendAAD ini iniState)
                (out, afterEncrypt) = CP.encrypt plain afterAAD
                outtag              = CP.finalize afterEncrypt
             in (out, outtag)

        input64 = B.replicate 64 0
        input1024 = B.replicate 1024 0

        nonce12 :: B.ByteString
        nonce12 = B.replicate 12 0

        key32 = B.replicate 32 0

benchECC =
    [ bench "pointAddTwoMuls-baseline"  $ nf run_b (n1, p1, n2, p2)
    , bench "pointAddTwoMuls-optimized" $ nf run_o (n1, p1, n2, p2)
    ]
  where run_b (n, p, k, q) = ECC.pointAdd c (ECC.pointMul c n p)
                                            (ECC.pointMul c k q)

        run_o (n, p, k, q) = ECC.pointAddTwoMuls c n p k q

        c  = ECC.getCurveByName ECC.SEC_p256r1
        r1 = 7
        r2 = 11
        p1 = ECC.pointBaseMul c r1
        p2 = ECC.pointBaseMul c r2
        n1 = 0x2ba9daf2363b2819e69b34a39cf496c2458a9b2a21505ea9e7b7cbca42dc7435
        n2 = 0xf054a7f60d10b8c2cf847ee90e9e029f8b0e971b09ca5f55c4d49921a11fadc1

data CurveDH = forall c . (EllipticCurveDH c, NFData (Scalar c), NFData (Point c)) => CurveDH c

benchECDH = map doECDHBench curves
  where
    doECDHBench (name, CurveDH c) =
        let proxy = Just c -- using Maybe as Proxy
         in env (generate proxy) $ bench name . nf (run proxy)

    generate proxy = do
        KeyPair _      aScalar <- curveGenerateKeyPair proxy
        KeyPair bPoint _       <- curveGenerateKeyPair proxy
        return (aScalar, bPoint)

    run proxy (s, p) = throwCryptoError (ecdh proxy s p)

    curves = [ ("P256R1", CurveDH Curve_P256R1)
             , ("P384R1", CurveDH Curve_P384R1)
             , ("P521R1", CurveDH Curve_P521R1)
             , ("X25519", CurveDH Curve_X25519)
             , ("X448",   CurveDH Curve_X448)
             ]

main = defaultMain
    [ bgroup "hash" benchHash
    , bgroup "block-cipher" benchBlockCipher
    , bgroup "AE" benchAE
    , bgroup "pbkdf2" benchPBKDF2
    , bgroup "ECC" benchECC
    , bgroup "ECDH" benchECDH
    , bgroup "F2m" benchF2m
    ]
