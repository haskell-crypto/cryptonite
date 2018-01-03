-- |
-- Module      : Crypto.PubKey.ECDSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Elliptic Curve Digital Signature Algorithm, with the parameterized
-- curve implementations provided by module "Crypto.ECC".
--
-- Public/private key pairs can be generated using
-- 'curveGenerateKeyPair' or decoded from binary.
--
-- /WARNING:/ Only curve P-256 has constant-time implementation.
-- Signature operations with P-384 and P-521 may leak the private key.
--
-- Signature verification should be safe for all curves.
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.PubKey.ECDSA
    ( EllipticCurveECDSA
    -- * Public keys
    , PublicKey
    , encodePublic
    , decodePublic
    , toPublic
    -- * Private keys
    , PrivateKey
    , encodePrivate
    , decodePrivate
    -- * Signatures
    , Signature(..)
    , signatureFromIntegers
    , signatureToIntegers
    -- * Scalars
    -- $scalars
    , scalarFromInteger
    , scalarToInteger
    -- * Generation and verification
    , signWith
    , sign
    , verify
    ) where

import           Control.Applicative
import           Control.Monad

import           Crypto.ECC
import qualified Crypto.ECC.Simple.Prim as Simple
import qualified Crypto.ECC.Simple.Types as Simple
import           Crypto.Error
import           Crypto.Hash
import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Imports
import           Crypto.Number.Basic (numBits)
import           Crypto.Number.ModArithmetic (inverse)
import           Crypto.Number.Serialize
import qualified Crypto.PubKey.ECC.P256 as P256
import           Crypto.Random.Types

import           Data.Bits (shiftR)
import           Data.Data

-- | Represent a ECDSA signature namely R and S.
data Signature curve = Signature
    { sign_r :: Scalar curve -- ^ ECDSA r
    , sign_s :: Scalar curve -- ^ ECDSA s
    }

deriving instance Eq (Scalar curve) => Eq (Signature curve)
deriving instance Show (Scalar curve) => Show (Signature curve)

instance NFData (Scalar curve) => NFData (Signature curve) where
    rnf (Signature r s) = rnf r `seq` rnf s `seq` ()

-- | ECDSA Public Key.
type PublicKey curve = Point curve

-- | ECDSA Private Key.
type PrivateKey curve = Scalar curve

-- | Elliptic curves with ECDSA capabilities.
class BaseEllipticCurveECDSA curve => EllipticCurveECDSA curve

instance EllipticCurveECDSA Curve_P256R1
instance EllipticCurveECDSA Curve_P384R1
instance EllipticCurveECDSA Curve_P521R1

class (EllipticCurveArith curve, Eq (Scalar curve)) => BaseEllipticCurveECDSA curve where

    scFromInteger :: proxy curve -> Integer -> CryptoFailable (Scalar curve)
    scToInteger :: proxy curve -> Scalar curve -> Integer

    encodeScalar :: ByteArray bs => proxy curve -> Scalar curve -> bs
    decodeScalar :: ByteArray bs => proxy curve -> bs -> CryptoFailable (Scalar curve)

    scalarIsZero :: proxy curve -> Scalar curve -> Bool
    scalarIsValid :: proxy curve -> Scalar curve -> Bool

    scalarAdd :: proxy curve -> Scalar curve -> Scalar curve -> Scalar curve
    scalarMul :: proxy curve -> Scalar curve -> Scalar curve -> Scalar curve
    scalarInv :: proxy curve -> Scalar curve -> Maybe (Scalar curve)

    curveOrderBits :: proxy curve -> Int

    toPoint :: proxy curve -> Scalar curve -> Point curve
    pointX :: proxy curve -> Point curve -> Maybe (Scalar curve)
    pointsMulVarTime :: proxy curve -> Scalar curve -> Scalar curve -> Point curve -> Point curve

instance BaseEllipticCurveECDSA Curve_P256R1 where

    encodeScalar _ = P256.scalarToBinary
    decodeScalar _ = P256.scalarFromBinary

    scFromInteger _ = P256.scalarFromInteger
    scToInteger _ = P256.scalarToInteger

    scalarIsZero _ = P256.scalarIsZero
    scalarIsValid _ s = not (P256.scalarIsZero s)
                            && P256.scalarCmp s P256.scalarN == LT

    scalarAdd _ = P256.scalarAdd
    scalarMul _ = P256.scalarMul
    scalarInv _ s = let inv = P256.scalarInvSafe s
                     in if P256.scalarIsZero inv then Nothing else Just inv

    curveOrderBits _ = 256

    toPoint _ = P256.toPoint
    pointX _  = P256.pointX
    pointsMulVarTime _ = P256.pointsMulVarTime

instance BaseEllipticCurveECDSA Curve_P384R1 where

    encodeScalar _ = ecScalarToBinary
    decodeScalar _ = ecScalarFromBinary

    scFromInteger _ = ecScalarFromInteger
    scToInteger _ = ecScalarToInteger

    scalarIsZero _ (Simple.Scalar s) = s == 0
    scalarIsValid _ = ecScalarIsValid (Proxy :: Proxy Simple.SEC_p384r1)

    scalarAdd _ = ecScalarAdd (Proxy :: Proxy Simple.SEC_p384r1)
    scalarMul _ = ecScalarMul (Proxy :: Proxy Simple.SEC_p384r1)
    scalarInv _ = ecScalarInv (Proxy :: Proxy Simple.SEC_p384r1)

    curveOrderBits _ = 384

    toPoint _ = Simple.pointBaseMul
    pointX _  = ecPointX (Proxy :: Proxy Simple.SEC_p384r1)
    pointsMulVarTime _ = ecPointsMulVarTime (Proxy :: Proxy Simple.SEC_p384r1)

instance BaseEllipticCurveECDSA Curve_P521R1 where

    encodeScalar _ = ecScalarToBinary
    decodeScalar _ = ecScalarFromBinary

    scFromInteger _ = ecScalarFromInteger
    scToInteger _ = ecScalarToInteger

    scalarIsZero _ (Simple.Scalar s) = s == 0
    scalarIsValid _ = ecScalarIsValid (Proxy :: Proxy Simple.SEC_p521r1)

    scalarAdd _ = ecScalarAdd (Proxy :: Proxy Simple.SEC_p521r1)
    scalarMul _ = ecScalarMul (Proxy :: Proxy Simple.SEC_p521r1)
    scalarInv _ = ecScalarInv (Proxy :: Proxy Simple.SEC_p521r1)

    curveOrderBits _ = 521

    toPoint _ = Simple.pointBaseMul
    pointX _  = ecPointX (Proxy :: Proxy Simple.SEC_p521r1)
    pointsMulVarTime _ = ecPointsMulVarTime (Proxy :: Proxy Simple.SEC_p521r1)


-- | Create a signature from integers (R, S).
signatureFromIntegers :: EllipticCurveECDSA curve
                      => proxy curve -> (Integer, Integer) -> CryptoFailable (Signature curve)
signatureFromIntegers prx (r, s) =
    liftA2 Signature (scalarFromInteger prx r) (scalarFromInteger prx s)

-- | Get integers (R, S) from a signature.
--
-- The values can then be used to encode the signature to binary with
-- ASN.1.
signatureToIntegers :: EllipticCurveECDSA curve
                    => proxy curve -> Signature curve -> (Integer, Integer)
signatureToIntegers prx sig =
    (scalarToInteger prx $ sign_r sig, scalarToInteger prx $ sign_s sig)

-- | Encode a public key into binary form, i.e. the uncompressed encoding
-- referenced from <https://tools.ietf.org/html/rfc5480 RFC 5480> section 2.2.
encodePublic :: (EllipticCurve curve, ByteArray bs)
             => proxy curve -> PublicKey curve -> bs
encodePublic = encodePoint

-- | Try to decode the binary form of a public key.
decodePublic :: (EllipticCurve curve, ByteArray bs)
             => proxy curve -> bs -> CryptoFailable (PublicKey curve)
decodePublic = decodePoint

-- | Encode a private key into binary form, i.e. the @privateKey@ field
-- described in <https://tools.ietf.org/html/rfc5915 RFC 5915>.
encodePrivate :: (EllipticCurveECDSA curve, ByteArray bs)
              => proxy curve -> PrivateKey curve -> bs
encodePrivate = encodeScalar

-- | Try to decode the binary form of a private key.
decodePrivate :: (EllipticCurveECDSA curve, ByteArray bs)
              => proxy curve -> bs -> CryptoFailable (PrivateKey curve)
decodePrivate = decodeScalar

-- | Create a public key from a private key.
toPublic :: EllipticCurveECDSA curve
         => proxy curve -> PrivateKey curve -> PublicKey curve
toPublic = toPoint

-- $scalars
--
-- Random scalars are generated using 'curveGenerateScalar'.
--
-- Conversion to/from 'Integer' is also provided but this
-- transformation to variable-size data type may leak information.

-- | Create a scalar from an integer.
scalarFromInteger :: EllipticCurveECDSA curve
                  => proxy curve -> Integer -> CryptoFailable (Scalar curve)
scalarFromInteger = scFromInteger

-- | Transform a scalar to an integer.
scalarToInteger :: EllipticCurveECDSA curve
                => proxy curve -> Scalar curve -> Integer
scalarToInteger = scToInteger


-- | Sign message using the private key and an explicit k scalar.
signWith :: (EllipticCurveECDSA curve, ByteArrayAccess msg, HashAlgorithm hash)
         => proxy curve -> Scalar curve -> PrivateKey curve -> hash -> msg -> Maybe (Signature curve)
signWith prx k d hashAlg msg = do
    let z = tHash prx hashAlg msg
        point = toPoint prx k
    r <- pointX prx point
    kInv <- scalarInv prx k
    let s = scalarMul prx kInv (scalarAdd prx z (scalarMul prx r d))
    when (scalarIsZero prx r || scalarIsZero prx s) Nothing
    return $ Signature r s

-- | Sign a message using hash and private key.
sign :: (EllipticCurveECDSA curve, MonadRandom m, ByteArrayAccess msg, HashAlgorithm hash)
     => proxy curve -> PrivateKey curve -> hash -> msg -> m (Signature curve)
sign prx pk hashAlg msg = do
    k <- curveGenerateScalar prx
    case signWith prx k pk hashAlg msg of
        Nothing  -> sign prx pk hashAlg msg
        Just sig -> return sig

-- | Verify a signature using hash and public key.
verify :: (EllipticCurveECDSA curve, ByteArrayAccess msg, HashAlgorithm hash)
       => proxy curve -> hash -> PublicKey curve -> Signature curve -> msg -> Bool
verify prx hashAlg q (Signature r s) msg
    | not (scalarIsValid prx r) = False
    | not (scalarIsValid prx s) = False
    | otherwise = maybe False (== r) $ do
        w <- scalarInv prx s
        let z  = tHash prx hashAlg msg
            u1 = scalarMul prx z w
            u2 = scalarMul prx r w
            x  = pointsMulVarTime prx u1 u2 q
        pointX prx x
    -- Note: precondition q /= PointO is not tested because we assume
    -- point decoding never decodes point at infinity.

-- | Truncate and hash.
tHash :: (EllipticCurveECDSA curve, ByteArrayAccess msg, HashAlgorithm hash)
      => proxy curve -> hash -> msg -> Scalar curve
tHash prx hashAlg m =
    throwCryptoError $ scalarFromInteger prx (if d > 0 then shiftR e d else e)
  where e = os2ip $ hashWith hashAlg m
        d = hashDigestSize hashAlg * 8 - curveOrderBits prx


ecScalarFromBinary :: forall curve bs . (Simple.Curve curve, ByteArrayAccess bs)
                   => bs -> CryptoFailable (Simple.Scalar curve)
ecScalarFromBinary ba
    | B.length ba /= size = CryptoFailed CryptoError_SecretKeySizeInvalid
    | otherwise           = CryptoPassed (Simple.Scalar $ os2ip ba)
  where size = ecCurveOrderBytes (Proxy :: Proxy curve)

ecScalarToBinary :: forall curve bs . (Simple.Curve curve, ByteArray bs)
                 => Simple.Scalar curve -> bs
ecScalarToBinary (Simple.Scalar s) = i2ospOf_ size s
  where size = ecCurveOrderBytes (Proxy :: Proxy curve)

ecScalarFromInteger :: forall curve . Simple.Curve curve
                    => Integer -> CryptoFailable (Simple.Scalar curve)
ecScalarFromInteger s
    | numBits s > nb = CryptoFailed CryptoError_SecretKeySizeInvalid
    | otherwise      = CryptoPassed (Simple.Scalar s)
  where nb = 8 * ecCurveOrderBytes (Proxy :: Proxy curve)

ecScalarToInteger :: Simple.Scalar curve -> Integer
ecScalarToInteger (Simple.Scalar s) = s

ecScalarIsValid :: Simple.Curve c => proxy c -> Simple.Scalar c -> Bool
ecScalarIsValid prx (Simple.Scalar s) = s > 0 && s < n
  where n = Simple.curveEccN $ Simple.curveParameters prx

ecScalarAdd :: Simple.Curve c
            => proxy c -> Simple.Scalar c -> Simple.Scalar c -> Simple.Scalar c
ecScalarAdd prx (Simple.Scalar a) (Simple.Scalar b) =
    Simple.Scalar ((a + b) `mod` n)
  where n = Simple.curveEccN $ Simple.curveParameters prx

ecScalarMul :: Simple.Curve c
            => proxy c -> Simple.Scalar c -> Simple.Scalar c -> Simple.Scalar c
ecScalarMul prx (Simple.Scalar a) (Simple.Scalar b) =
    Simple.Scalar ((a * b) `mod` n)
  where n = Simple.curveEccN $ Simple.curveParameters prx

ecScalarInv :: Simple.Curve c
            => proxy c -> Simple.Scalar c -> Maybe (Simple.Scalar c)
ecScalarInv prx (Simple.Scalar s) = Simple.Scalar `fmap` inverse s n
  where n = Simple.curveEccN $ Simple.curveParameters prx

ecPointX :: Simple.Curve c
         => proxy c -> Simple.Point c -> Maybe (Simple.Scalar c)
ecPointX _   Simple.PointO      = Nothing
ecPointX prx (Simple.Point x _) = Just (Simple.Scalar $ x `mod` n)
  where n = Simple.curveEccN $ Simple.curveParameters prx

ecPointsMulVarTime :: Simple.Curve c
                   => proxy c -> Simple.Scalar c -> Simple.Scalar c
                   -> Simple.Point c -> Simple.Point c
ecPointsMulVarTime prx n1 n2 p = Simple.pointAddTwoMuls n1 g n2 p
  where g = Simple.curveEccG $ Simple.curveParameters prx

ecCurveOrderBytes :: Simple.Curve c => proxy c -> Int
ecCurveOrderBytes prx = (numBits n + 7) `div` 8
  where n = Simple.curveEccN $ Simple.curveParameters prx
