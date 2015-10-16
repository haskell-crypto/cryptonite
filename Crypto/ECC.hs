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
module Crypto.ECC
    ( Curve_P256R1(..)
    , Curve_P521R1(..)
    , EllipticCurve(..)
    , EllipticCurveDH(..)
    , EllipticCurveArith(..)
    , KeyPair(..)
    , SharedSecret(..)
    ) where

import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.Types as H
import qualified Crypto.PubKey.ECC.Prim as H
import           Crypto.Random
import           Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import           Data.Function (on)

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
    data Point curve  :: *

    -- | Scalar in the Elliptic Curve domain
    data Scalar curve :: *

    -- | get the order of the Curve
    curveGetOrder :: curve -> Integer

    -- | get the curve related to a point on a curve
    curveOfPoint :: Point curve -> curve

    -- | get the curve related to a curve's scalar
    curveOfScalar :: Scalar curve -> curve

    -- | get the base point of the Curve
    curveGetBasePoint :: Point curve

    -- | Generate a new random scalar on the curve.
    -- The scalar will represent a number between 1 and the order of the curve non included
    curveGenerateScalar :: MonadRandom randomly => randomly (Scalar curve)

    -- | Generate a new random keypair
    curveGenerateKeyPair :: MonadRandom randomly => randomly (KeyPair curve)

class EllipticCurve curve => EllipticCurveDH curve where
    -- | Generate a Diffie hellman secret
    ecdh :: Scalar curve -> Point curve -> SharedSecret

class EllipticCurve curve => EllipticCurveArith curve where
    -- | Add points on a curve
    pointAdd :: Point curve -> Point curve -> Point curve

    -- | Scalar Multiplication on a curve
    pointSmul :: Scalar curve -> Point curve -> Point curve

-- | P256 Curve
--
-- also known as P256
data Curve_P256R1 = Curve_P256R1

instance EllipticCurve Curve_P256R1 where
    newtype Point Curve_P256R1 = P256Point { unP256Point :: P256.Point }
    newtype Scalar Curve_P256R1 = P256Scalar { unP256Scalar :: P256.Scalar }
    curveGetOrder     _ = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    curveGetBasePoint = P256Point P256.pointBase
    curveOfScalar _ = Curve_P256R1
    curveOfPoint _ = Curve_P256R1
    curveGenerateScalar = P256Scalar <$> P256.scalarGenerate
    curveGenerateKeyPair = toKeyPair <$> P256.scalarGenerate
      where toKeyPair scalar = KeyPair (P256Point $ P256.toPoint scalar) (P256Scalar scalar)
instance EllipticCurveArith Curve_P256R1 where
    pointAdd  a b = P256Point $ (P256.pointAdd `on` unP256Point) a b
    pointSmul s p = P256Point $ P256.pointMul (unP256Scalar s) (unP256Point p)
instance EllipticCurveDH Curve_P256R1 where
    ecdh s p = undefined

data Curve_P521R1 = Curve_P521R1

instance EllipticCurve Curve_P521R1 where
    newtype Point Curve_P521R1 = P521Point { unP521Point :: H.Point }
    newtype Scalar Curve_P521R1 = P521Scalar { unP521Scalar :: H.PrivateNumber }
    curveGetOrder _ = H.ecc_n $ H.common_curve $ H.getCurveByName H.SEC_p521r1
    curveGetBasePoint = P521Point $ H.ecc_g $ H.common_curve $ H.getCurveByName H.SEC_p521r1
    curveOfScalar _ = Curve_P521R1
    curveOfPoint _ = Curve_P521R1
    curveGenerateScalar = P521Scalar <$> H.scalarGenerate (H.getCurveByName H.SEC_p521r1)
    curveGenerateKeyPair = toKeyPair <$> H.scalarGenerate (H.getCurveByName H.SEC_p521r1)
      where toKeyPair scalar = KeyPair (P521Point $ H.pointBaseMul (H.getCurveByName H.SEC_p521r1) scalar) (P521Scalar scalar)
instance EllipticCurveArith Curve_P521R1 where
    pointAdd a b = P521Point $ (H.pointAdd (H.getCurveByName H.SEC_p521r1) `on` unP521Point) a b
    pointSmul s p = P521Point (H.pointMul (H.getCurveByName H.SEC_p521r1) (unP521Scalar s) (unP521Point p))

