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
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE StandaloneDeriving #-}

module Crypto.ECC (
      Curve(..)
    , EllipticCurve(..)
    , Curve_P256R1(..)
    , Curve_P384R1(..)
    , Curve_P521R1(..)
    , KeyPair(..)
    , CurveKeyPair(..)
    , generateKeyPair
    , curveBytes
    , SharedSecret(..)
    ) where

import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.PubKey.ECC.Prim as H
import qualified Crypto.PubKey.ECC.Types as H
import           Crypto.Random
import           Crypto.Internal.Imports
import           Crypto.Internal.ByteArray (ByteArrayAccess, ScrubbedBytes)
import           Data.Function (on)

----------------------------------------------------------------

data Curve = forall c. (EllipticCurve c, Eq c, Show c) => Curve c

instance Eq Curve where
    Curve x == Curve y = curveName x == curveName y

instance Show Curve where
    show (Curve c) = show c

----------------------------------------------------------------

class EllipticCurve curve where
    -- | Point on an Elliptic Curve
    data Point curve  :: *

    -- | Scalar in the Elliptic Curve domain
    data Scalar curve :: *

    curveName :: curve -> String

    -- | get the order of the Curve
    curveGetOrder :: curve -> Integer

    -- | get the curve related to a point on a curve
    curveOfPoint :: Point curve -> curve

    -- | get the curve related to a curve's scalar
    curveOfScalar :: Scalar curve -> curve

    -- | get the base point of the Curve
    curveGetBasePoint :: Point curve

    curveIsPointValid :: Point curve -> Bool

    -- | Generate a new random scalar on the curve.
    -- The scalar will represent a number between 1 and the order of the curve non included
    curveGenerateScalar :: MonadRandom randomly => curve -> randomly (Scalar curve)
    curveNbBits :: curve -> Int

    curveScalarToInteger :: Scalar curve -> Integer

    curveScalarToPoint :: Scalar curve -> Point curve

    curvePointToIntegers :: Point curve -> (Integer, Integer)

    curveIntegersToPoint :: curve -> Integer -> Integer -> Point curve

    -- | Add points on a curve
    curvePointAdd :: Point curve -> Point curve -> Point curve

    -- | Scalar Multiplication on a curve
    curvePointSmul :: Scalar curve -> Point curve -> Point curve

--   -- | Scalar Inverse
--   scalarInverse :: Scalar curve -> Scalar curve


instance EllipticCurve a => Eq (Scalar a) where
    x == y = curveScalarToInteger x == curveScalarToInteger y

instance EllipticCurve a => Show (Scalar a) where
    show x = show (curveScalarToInteger x)

instance EllipticCurve a => Eq (Point a) where
    x == y = curvePointToIntegers x == curvePointToIntegers y

instance EllipticCurve a => Show (Point a) where
    show x = show (curvePointToIntegers x)

----------------------------------------------------------------

-- | P256 Curve
--
-- also known as P256
data Curve_P256R1 = Curve_P256R1 deriving (Eq, Show)

instance EllipticCurve Curve_P256R1 where
    newtype Point Curve_P256R1 = P256Point { unP256Point :: P256.Point }
    newtype Scalar Curve_P256R1 = P256Scalar { unP256Scalar :: P256.Scalar }
    curveName _ = "P256R1"
    curveGetOrder     _ = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    curveGetBasePoint = P256Point P256.pointBase
    curveOfScalar _ = Curve_P256R1
    curveOfPoint _ = Curve_P256R1
    curveIsPointValid p = P256.pointIsValid $ unP256Point p
    curveGenerateScalar _ = P256Scalar <$> P256.scalarGenerate
    curveScalarToInteger s = P256.scalarToInteger $ unP256Scalar s
    curveScalarToPoint s = P256Point $ P256.toPoint (unP256Scalar s)
    curvePointToIntegers p = P256.pointToIntegers $ unP256Point p
    curveIntegersToPoint _ x y = P256Point $ P256.pointFromIntegers (x,y)
    curvePointAdd  a b = P256Point $ (P256.pointAdd `on` unP256Point) a b
    curvePointSmul s p = P256Point $ P256.pointMul (unP256Scalar s) (unP256Point p)
    curveNbBits _ = 256

----------------------------------------------------------------

data Curve_P384R1 = Curve_P384R1 deriving (Eq, Show)

instance EllipticCurve Curve_P384R1 where
    newtype Point Curve_P384R1 = P384Point { unP384Point :: H.Point }
    newtype Scalar Curve_P384R1 = P384Scalar { unP384Scalar :: H.PrivateNumber }
    curveName _ = "P384R1"
    curveGetOrder _ = H.ecc_n $ H.common_curve $ H.getCurveByName H.SEC_p384r1
    curveGetBasePoint = P384Point $ H.ecc_g $ H.common_curve $ H.getCurveByName H.SEC_p384r1
    curveOfScalar _ = Curve_P384R1
    curveOfPoint _ = Curve_P384R1
    curveIsPointValid p = H.isPointValid (H.getCurveByName H.SEC_p384r1) (unP384Point p)
    curveGenerateScalar _ = P384Scalar <$> H.scalarGenerate (H.getCurveByName H.SEC_p384r1)
    curveScalarToInteger s = unP384Scalar s
    curveScalarToPoint s = P384Point $ H.pointBaseMul (H.getCurveByName H.SEC_p384r1) (unP384Scalar s)
    curvePointToIntegers p = (x, y)
      where
        H.Point x y = unP384Point p
    curveIntegersToPoint _ x y = P384Point $ H.Point x y
    curvePointAdd a b = P384Point $ (H.pointAdd (H.getCurveByName H.SEC_p384r1) `on` unP384Point) a b
    curvePointSmul s p = P384Point (H.pointMul (H.getCurveByName H.SEC_p384r1) (unP384Scalar s) (unP384Point p))
    curveNbBits _ = 384

----------------------------------------------------------------

data Curve_P521R1 = Curve_P521R1 deriving (Eq, Show)

instance EllipticCurve Curve_P521R1 where
    newtype Point Curve_P521R1 = P521Point { unP521Point :: H.Point }
    newtype Scalar Curve_P521R1 = P521Scalar { unP521Scalar :: H.PrivateNumber }
    curveName _ = "P521R1"
    curveGetOrder _ = H.ecc_n $ H.common_curve $ H.getCurveByName H.SEC_p521r1
    curveGetBasePoint = P521Point $ H.ecc_g $ H.common_curve $ H.getCurveByName H.SEC_p521r1
    curveOfScalar _ = Curve_P521R1
    curveOfPoint _ = Curve_P521R1
    curveIsPointValid p = H.isPointValid (H.getCurveByName H.SEC_p521r1) (unP521Point p)
    curveGenerateScalar _ = P521Scalar <$> H.scalarGenerate (H.getCurveByName H.SEC_p521r1)
    curveScalarToInteger s = unP521Scalar s
    curveScalarToPoint s = P521Point $ H.pointBaseMul (H.getCurveByName H.SEC_p521r1) (unP521Scalar s)
    curvePointToIntegers p = (x, y)
      where
        H.Point x y = unP521Point p
    curveIntegersToPoint _ x y = P521Point $ H.Point x y
    curvePointAdd a b = P521Point $ (H.pointAdd (H.getCurveByName H.SEC_p521r1) `on` unP521Point) a b
    curvePointSmul s p = P521Point (H.pointMul (H.getCurveByName H.SEC_p521r1) (unP521Scalar s) (unP521Point p))
    curveNbBits _ = 521

----------------------------------------------------------------

-- | An elliptic curve key pair composed of the private part (a scalar), and
-- the associated point.
data KeyPair curve = KeyPair {
      keypairPublic  :: !(Point curve)
    , keypairPrivate :: !(Scalar curve)
    } deriving (Eq, Show)

data CurveKeyPair = forall c. (EllipticCurve c, Eq c, Show c) => CurveKeyPair (KeyPair c)

instance Eq CurveKeyPair where
    CurveKeyPair x == CurveKeyPair y =
        curvePointToIntegers (keypairPublic x) == curvePointToIntegers (keypairPublic y) &&
        curveScalarToInteger (keypairPrivate x) == curveScalarToInteger (keypairPrivate y)

instance Show CurveKeyPair where
    show (CurveKeyPair x) = show x

-- | Generating a pair of private key (scalar d) and public key (point Q).
generateKeyPair :: MonadRandom randomly => Curve -> randomly CurveKeyPair
generateKeyPair (Curve curve) = do
    s <- curveGenerateScalar curve
    let p = curveScalarToPoint s
    return $ CurveKeyPair (KeyPair p s)

----------------------------------------------------------------

curveBytes :: EllipticCurve c => c -> Int
curveBytes c = (curveNbBits c + 7) `div` 8

----------------------------------------------------------------

newtype SharedSecret = SharedSecret ScrubbedBytes
    deriving (Eq, ByteArrayAccess)
