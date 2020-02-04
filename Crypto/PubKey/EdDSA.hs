-- |
-- Module      : Crypto.PubKey.EdDSA
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- EdDSA signature generation and verification.
--
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeFamilies               #-}
module Crypto.PubKey.EdDSA
    ( SecretKey
    , PublicKey
    , Signature
    -- * Curves with EdDSA implementation
    , EllipticCurveEdDSA(publicKeySize, secretKeySize, signatureSize)
    -- * Smart constructors
    , signature
    , publicKey
    , secretKey
    -- * Methods
    , toPublic
    , sign
    , verify
    , generateSecretKey
    ) where

import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess, Bytes, ScrubbedBytes, View)
import qualified Data.ByteArray as B

import           Crypto.ECC
import qualified Crypto.ECC.Edwards25519 as Edwards25519
import           Crypto.Error
import           Crypto.Hash
import           Crypto.Random

import           Crypto.Internal.Imports

import           Foreign.Storable


-- API

-- | An EdDSA Secret key
newtype SecretKey curve = SecretKey ScrubbedBytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | An EdDSA public key
newtype PublicKey curve = PublicKey Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | An EdDSA signature
newtype Signature curve = Signature Bytes
    deriving (Show,Eq,ByteArrayAccess,NFData)

-- | Elliptic curves with an implementation of EdDSA
class ( EllipticCurveBasepointArith curve
      , HashAlgorithm (HashAlg curve)
      ) => EllipticCurveEdDSA curve where

    -- | Size of public keys for this curve (in bytes)
    publicKeySize :: proxy curve -> Int

    -- | Size of secret keys for this curve (in bytes)
    secretKeySize :: proxy curve -> Int

    -- | Size of signatures for this curve (in bytes)
    signatureSize :: proxy curve -> Int

    -- prepare hash context with specified parameters
    type HashAlg curve :: *
    hashInitWithDom :: proxy curve -> Context (HashAlg curve)

    -- conversion between scalar, point and public key
    pointPublic :: proxy curve -> Point curve -> PublicKey curve
    publicPoint :: proxy curve -> PublicKey curve -> CryptoFailable (Point curve)
    encodeScalarLE :: ByteArray bs => proxy curve -> Scalar curve -> bs
    decodeScalarLE :: ByteArrayAccess bs => proxy curve -> bs -> CryptoFailable (Scalar curve)

    -- how to use bits in a secret key
    scheduleSecret :: proxy curve
                   -> SecretKey curve
                   -> (Scalar curve, View (Digest (HashAlg curve)))


-- Constructors

-- | Try to build a public key from a bytearray
publicKey :: (EllipticCurveEdDSA curve, ByteArrayAccess ba)
          => proxy curve -> ba -> CryptoFailable (PublicKey curve)
publicKey prx bs
    | B.length bs == publicKeySize prx =
        CryptoPassed (PublicKey $ B.convert bs)
    | otherwise =
        CryptoFailed CryptoError_PublicKeySizeInvalid

-- | Try to build a secret key from a bytearray
secretKey :: (EllipticCurveEdDSA curve, ByteArrayAccess ba)
          => proxy curve -> ba -> CryptoFailable (SecretKey curve)
secretKey prx bs
    | B.length bs == secretKeySize prx =
        CryptoPassed (SecretKey $ B.convert bs)
    | otherwise                        =
        CryptoFailed CryptoError_SecretKeyStructureInvalid

-- | Try to build a signature from a bytearray
signature :: (EllipticCurveEdDSA curve, ByteArrayAccess ba)
          => proxy curve -> ba -> CryptoFailable (Signature curve)
signature prx bs
    | B.length bs == signatureSize prx =
        CryptoPassed (Signature $ B.convert bs)
    | otherwise =
        CryptoFailed CryptoError_SecretKeyStructureInvalid


-- Conversions

-- | Generate a secret key
generateSecretKey :: (EllipticCurveEdDSA curve, MonadRandom m)
                  => proxy curve -> m (SecretKey curve)
generateSecretKey prx = SecretKey <$> getRandomBytes (secretKeySize prx)

-- | Create a public key from a secret key
toPublic :: EllipticCurveEdDSA curve
         => proxy curve -> SecretKey curve -> PublicKey curve
toPublic prx priv =
    let p = pointBaseSmul prx (secretScalar prx priv)
     in pointPublic prx p

secretScalar :: EllipticCurveEdDSA curve
             => proxy curve -> SecretKey curve -> Scalar curve
secretScalar prx priv = fst (scheduleSecret prx priv)


-- EdDSA signature generation & verification

-- | Sign a message using the key pair
sign :: (EllipticCurveEdDSA curve, ByteArrayAccess msg)
     => proxy curve -> SecretKey curve -> PublicKey curve -> msg -> Signature curve
sign prx priv pub msg =
    let (s, prefix) = scheduleSecret prx priv
        digR = hashFinalize $ hashUpdate (hashUpdate (hashInitWithDom prx) prefix) msg
        r    = decodeScalarNoErr prx digR
        pR   = pointBaseSmul prx r
        bsR  = encodePoint prx pR
        sK   = getK prx pub bsR msg
        sS   = scalarAdd prx r (scalarMul prx sK s)
     in encodeSignature prx (bsR, pR, sS)

-- | Verify a message
verify :: (EllipticCurveEdDSA curve, ByteArrayAccess msg)
       => proxy curve -> PublicKey curve -> msg -> Signature curve -> Bool
verify prx pub msg sig =
    case doVerify of
        CryptoPassed verified -> verified
        CryptoFailed _        -> False
  where
    doVerify = do
        (bsR, pR, sS) <- decodeSignature prx sig
        nPub <- pointNegate prx `fmap` publicPoint prx pub
        let sK  = getK prx pub bsR msg
            pR' = pointsSmulVarTime prx sS sK nPub
        return (pR == pR')

getK :: (EllipticCurveEdDSA curve, ByteArrayAccess msg)
     => proxy curve -> PublicKey curve -> Bytes -> msg -> Scalar curve
getK prx pub bsR msg =
    let digK = hashFinalize $ hashUpdate (hashUpdate (hashUpdate (hashInitWithDom prx) bsR) pub) msg
     in decodeScalarNoErr prx digK

encodeSignature :: EllipticCurveEdDSA curve
                => proxy curve
                -> (Bytes, Point curve, Scalar curve)
                -> Signature curve
encodeSignature prx (bsR, _, sS) = Signature $
    if len0 > 0 then B.concat [ bsR, bsS, pad0 ] else B.append bsR bsS
  where
    bsS  = encodeScalarLE prx sS
    len0 = signatureSize prx - B.length bsR - B.length bsS
    pad0 = B.zero len0

decodeSignature :: EllipticCurveEdDSA curve
                => proxy curve
                -> Signature curve
                -> CryptoFailable (Bytes, Point curve, Scalar curve)
decodeSignature prx (Signature bs) = do
    let (bsR, bsS) = B.splitAt (publicKeySize prx) bs
    pR <- decodePoint prx bsR
    sS <- decodeScalarLE prx bsS
    return (bsR, pR, sS)

-- implementations are supposed to decode any scalar up to the size of the digest
decodeScalarNoErr :: (EllipticCurveEdDSA curve, ByteArrayAccess bs)
                  => proxy curve -> bs -> Scalar curve
decodeScalarNoErr prx = unwrap "decodeScalarNoErr" . decodeScalarLE prx

unwrap :: String -> CryptoFailable a -> a
unwrap name (CryptoFailed _) = error (name ++ ": assumption failed")
unwrap _    (CryptoPassed x) = x


-- Ed25519 implementation

instance EllipticCurveEdDSA Curve_Edwards25519 where
    publicKeySize _ = 32
    secretKeySize _ = 32
    signatureSize _ = 64

    type HashAlg Curve_Edwards25519 = SHA512
    hashInitWithDom _ = hashInitWith SHA512

    pointPublic _ = PublicKey . Edwards25519.pointEncode
    publicPoint _ = Edwards25519.pointDecode
    encodeScalarLE _ = Edwards25519.scalarEncode
    decodeScalarLE _ = Edwards25519.scalarDecodeLong

    scheduleSecret prx priv =
        (decodeScalarNoErr prx clamped, B.dropView hashed 32)
      where
        hashed  = hashWith SHA512 priv

        clamped :: Bytes
        clamped = B.copyAndFreeze (B.takeView hashed 32) $ \p -> do
                      b0  <- peekElemOff p 0  :: IO Word8
                      b31 <- peekElemOff p 31 :: IO Word8
                      pokeElemOff p 31 ((b31 .&. 0x7F) .|. 0x40)
                      pokeElemOff p 0  (b0 .&. 0xF8)
