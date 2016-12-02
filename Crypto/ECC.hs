-- |
-- Module      : Crypto.ECC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Elliptic Curve Cryptography
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.ECC
    ( Curve_P256R1(..)
    , Curve_P384R1(..)
    , Curve_P521R1(..)
    , Curve_X25519(..)
    , EllipticCurve(..)
    , EllipticCurveDH(..)
    , EllipticCurveArith(..)
    , KeyPair(..)
    , SharedSecret(..)
    ) where

import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.ECC.Simple.Types as Simple
import qualified Crypto.ECC.Simple.Prim as Simple
import           Crypto.Random
import           Crypto.Error
import           Crypto.Internal.Proxy
import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Number.Serialize (i2ospOf_, os2ip)
import qualified Crypto.PubKey.Curve25519 as X25519
import           Data.Function (on)
import           Data.ByteArray (convert)

-- | An elliptic curve key pair composed of the private part (a scalar), and
-- the associated point.
data KeyPair curve = KeyPair
    { keypairGetPublic  :: !(Point curve)
    , keypairGetPrivate :: !(Scalar curve)
    }

newtype SharedSecret = SharedSecret ScrubbedBytes
    deriving (Eq, ByteArrayAccess)

class EllipticCurve curve where
    -- | Point on an Elliptic Curve
    type Point curve  :: *

    -- | Scalar in the Elliptic Curve domain
    type Scalar curve :: *

    -- | Generate a new random scalar on the curve.
    -- The scalar will represent a number between 1 and the order of the curve non included
    curveGenerateScalar :: MonadRandom randomly => proxy curve -> randomly (Scalar curve)

    -- | Generate a new random keypair
    curveGenerateKeyPair :: MonadRandom randomly => proxy curve -> randomly (KeyPair curve)

    -- | Get the curve size in bits
    curveSizeBits :: proxy curve -> Int

    -- | Encode a elliptic curve point into binary form
    encodePoint :: ByteArray bs => proxy curve -> Point curve -> bs

    -- | Try to decode the binary form of an elliptic curve point
    decodePoint :: ByteArray bs => proxy curve -> bs -> CryptoFailable (Point curve)

class EllipticCurve curve => EllipticCurveDH curve where
    -- | Generate a Diffie hellman secret value.
    --
    -- This is generally just the .x coordinate of the resulting point, that
    -- is not hashed.
    --
    -- use `pointSmul` to keep the result in Point format.
    ecdh :: proxy curve -> Scalar curve -> Point curve -> SharedSecret

class EllipticCurve curve => EllipticCurveArith curve where
    -- | Add points on a curve
    pointAdd :: proxy curve -> Point curve -> Point curve -> Point curve

    -- | Scalar Multiplication on a curve
    pointSmul :: proxy curve -> Scalar curve -> Point curve -> Point curve

--   -- | Scalar Inverse
--   scalarInverse :: Scalar curve -> Scalar curve

-- | P256 Curve
--
-- also known as P256
data Curve_P256R1 = Curve_P256R1

instance EllipticCurve Curve_P256R1 where
    type Point Curve_P256R1 = P256.Point
    type Scalar Curve_P256R1 = P256.Scalar
    curveSizeBits _ = 256
    curveGenerateScalar _ = P256.scalarGenerate
    curveGenerateKeyPair _ = toKeyPair <$> P256.scalarGenerate
      where toKeyPair scalar = KeyPair (P256.toPoint scalar) scalar
    encodePoint _ p = encodeECPoint (Simple.Point x y :: Simple.Point Simple.SEC_p256r1)
      where
        (x,y) = P256.pointToIntegers p
    decodePoint _ bs = fromSimplePoint <$> decodeECPoint bs
      where fromSimplePoint :: Simple.Point Simple.SEC_p256r1 -> P256.Point
            fromSimplePoint (Simple.Point x y) = P256.pointFromIntegers (x,y)
            fromSimplePoint Simple.PointO      = error "impossible happened: fromPoint is infinite"

instance EllipticCurveArith Curve_P256R1 where
    pointAdd  _ a b = P256.pointAdd a b
    pointSmul _ s p = P256.pointMul s p

instance EllipticCurveDH Curve_P256R1 where
    ecdh proxy s p = shared
      where
        (x, _) = P256.pointToIntegers $ pointSmul proxy s p
        len = 32 -- (256 + 7) `div` 8
        shared = SharedSecret $ i2ospOf_ len x

data Curve_P384R1 = Curve_P384R1

instance EllipticCurve Curve_P384R1 where
    type Point Curve_P384R1 = Simple.Point Simple.SEC_p384r1
    type Scalar Curve_P384R1 = Simple.Scalar Simple.SEC_p384r1
    curveSizeBits _ = 384
    curveGenerateScalar _ = Simple.scalarGenerate
    curveGenerateKeyPair _ = toKeyPair <$> Simple.scalarGenerate
      where toKeyPair scalar = KeyPair (Simple.pointBaseMul scalar) scalar
    encodePoint _ point = encodeECPoint point
    decodePoint _ bs = decodeECPoint bs

instance EllipticCurveArith Curve_P384R1 where
    pointAdd _ a b = Simple.pointAdd a b
    pointSmul _ s p = Simple.pointMul s p

instance EllipticCurveDH Curve_P384R1 where
    ecdh _ s p = SharedSecret $ i2ospOf_ (curveSizeBytes prx) x
      where
        prx = Proxy :: Proxy Curve_P384R1
        Simple.Point x _ = pointSmul prx s p

data Curve_P521R1 = Curve_P521R1

instance EllipticCurve Curve_P521R1 where
    type Point Curve_P521R1 = Simple.Point Simple.SEC_p521r1
    type Scalar Curve_P521R1 = Simple.Scalar Simple.SEC_p521r1
    curveSizeBits _ = 521
    curveGenerateScalar _ = Simple.scalarGenerate
    curveGenerateKeyPair _ = toKeyPair <$> Simple.scalarGenerate
      where toKeyPair scalar = KeyPair (Simple.pointBaseMul scalar) scalar
    encodePoint _ point = encodeECPoint point
    decodePoint _ bs = decodeECPoint bs

instance EllipticCurveArith Curve_P521R1 where
    pointAdd _ a b = Simple.pointAdd a b
    pointSmul _ s p = Simple.pointMul s p

instance EllipticCurveDH Curve_P521R1 where
    ecdh _ s p = SharedSecret $ i2ospOf_ (curveSizeBytes prx) x
      where
        prx = Proxy :: Proxy Curve_P521R1
        Simple.Point x _ = pointSmul prx s p

data Curve_X25519 = Curve_X25519

instance EllipticCurve Curve_X25519 where
    type Point Curve_X25519 = X25519.PublicKey
    type Scalar Curve_X25519 = X25519.SecretKey
    curveSizeBits _ = 255
    curveGenerateScalar _ = X25519.generateSecretKey
    curveGenerateKeyPair _ = do
        s <- X25519.generateSecretKey
        return $ KeyPair (X25519.toPublic s) s
    encodePoint _ p = B.convert p
    decodePoint _ bs = X25519.publicKey bs

instance EllipticCurveDH Curve_X25519 where
    ecdh _ s p = SharedSecret $ convert secret
      where secret = X25519.dh p s

encodeECPoint :: forall curve bs . (Simple.Curve curve, ByteArray bs) => Simple.Point curve -> bs
encodeECPoint Simple.PointO      = error "encodeECPoint: cannot serialize point at infinity"
encodeECPoint (Simple.Point x y) = B.concat [uncompressed,xb,yb]
  where
    size = Simple.curveSizeBytes (Proxy :: Proxy curve)
    uncompressed, xb, yb :: bs
    uncompressed = B.singleton 4
    xb = i2ospOf_ size x
    yb = i2ospOf_ size y

decodeECPoint :: (Simple.Curve curve, ByteArray bs) => bs -> CryptoFailable (Simple.Point curve)
decodeECPoint mxy = case B.uncons mxy of
    Nothing     -> CryptoFailed $ CryptoError_PointSizeInvalid
    Just (m,xy)
        -- uncompressed
        | m == 4 ->
            let siz = B.length xy `div` 2
                (xb,yb) = B.splitAt siz xy
                x = os2ip xb
                y = os2ip yb
             in CryptoPassed $ Simple.Point x y
        | otherwise -> CryptoFailed $ CryptoError_PointFormatInvalid

curveSizeBytes :: EllipticCurve c => Proxy c -> Int
curveSizeBytes proxy = (curveSizeBits proxy + 7) `div` 8
