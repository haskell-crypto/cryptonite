{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
module Main where

import Gauge.Main

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
import qualified Crypto.KDF.BCrypt as BCrypt
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import           Crypto.Number.Basic (numBits)
import           Crypto.Number.Generate
import qualified Crypto.PubKey.DH as DH
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

benchBCrypt =
    [ bench "cryptonite-BCrypt-4"  $ nf bcrypt 4
    , bench "cryptonite-BCrypt-5"  $ nf bcrypt 5
    , bench "cryptonite-BCrypt-7"  $ nf bcrypt 7
    , bench "cryptonite-BCrypt-11" $ nf bcrypt 11
    ]
  where
        bcrypt :: Int -> B.ByteString
        bcrypt cost = BCrypt.bcrypt cost mysalt mypass

        mypass, mysalt :: B.ByteString
        mypass = "password"
        mysalt = "saltsaltsaltsalt"

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
    [ bench "ChaChaPoly1305" $ nf (cp key32) (input64, input1024)
    , bench "AES-GCM" $ nf (gcm key32) (input64, input1024)
    , bench "AES-CCM" $ nf (ccm key32) (input64, input1024)
    ]
  where cp k (ini, plain) =
            let iniState            = throwCryptoError $ CP.initialize k (throwCryptoError $ CP.nonce12 nonce12)
                afterAAD            = CP.finalizeAAD (CP.appendAAD ini iniState)
                (out, afterEncrypt) = CP.encrypt plain afterAAD
                outtag              = CP.finalize afterEncrypt
             in (outtag, out)

        gcm k (ini, plain) =
            let ctx = throwCryptoError (cipherInit k) :: AES256
                state = throwCryptoError $ aeadInit AEAD_GCM ctx nonce12
             in aeadSimpleEncrypt state ini plain 16

        ccm k (ini, plain) =
            let ctx = throwCryptoError (cipherInit k) :: AES256
                mode = AEAD_CCM 1024 CCM_M16 CCM_L3
                state = throwCryptoError $ aeadInit mode ctx nonce12
             in aeadSimpleEncrypt state ini plain 16

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

benchFFDH = map doFFDHBench primes
  where
    doFFDHBench (e, p) =
        let bits = numBits p
            params = DH.Params { DH.params_p = p, DH.params_g = 2, DH.params_bits = bits }
         in env (generate e params) $ bench (show bits) . nf (run params)

    generate e params = do
        aPriv <- DH.PrivateNumber `fmap` generatePriv e
        bPriv <- DH.PrivateNumber `fmap` generatePriv e
        return (aPriv, DH.calculatePublic params bPriv)

    generatePriv e = generateParams e (Just SetHighest) False

    run params (priv, pub) = DH.getShared params priv pub

    -- RFC 7919: prime p with minimal size of exponent
    primes = [ (225, 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF)
             , (275, 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF)
             , (325, 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF)
             , (375, 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF)
             , (400, 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C8381E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E454504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF)
             ]

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
    , bgroup "bcrypt" benchBCrypt
    , bgroup "ECC" benchECC
    , bgroup "DH"
          [ bgroup "FFDH" benchFFDH
          , bgroup "ECDH" benchECDH
          ]
    , bgroup "F2m" benchF2m
    ]
