-- |
-- Module      : Crypto.PubKey.ECC.P256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- P256 support
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
module Crypto.PubKey.ECC.P256
    ( Scalar
    , Point
    -- * point arithmetic
    , pointAdd
    , pointMul
    , pointsMulVarTime
    , pointIsValid
    , toPoint
    -- * scalar arithmetic
    , scalarZero
    , scalarAdd
    , scalarSub
    , scalarInv
    , scalarInvVarTime
    , scalarCmp
    , scalarFromBinary
    , scalarToBinary
    ) where

import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
--import           Crypto.Internal.Memory
import           Crypto.Internal.ByteArray
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Error

-- | A P256 scalar
newtype Scalar = Scalar ScrubbedBytes
    deriving (Eq,ByteArrayAccess)

-- | A P256 point
data Point = Point !Bytes !Bytes
    deriving (Show,Eq)

scalarSize :: Int
scalarSize = 32

type P256Digit  = Word32

data P256Scalar
data P256Y
data P256X

------------------------------------------------------------------------
-- Point methods
------------------------------------------------------------------------


-- | Lift to curve a scalar
--
-- Using the curve generator as base point compute:
--
-- > scalar * G
--
toPoint :: Scalar -> Point
toPoint s = withNewPoint $ \px py -> withScalar s $ \p ->
    ccryptonite_p256_basepoint_mul p px py

-- | Add a point to another point
pointAdd :: Point -> Point -> Point
pointAdd a b = withNewPoint $ \dx dy ->
    withPoint a $ \ax ay -> withPoint b $ \bx by ->
        ccryptonite_p256e_point_add ax ay bx by dx dy

-- | Multiply a point by a scalar
pointMul :: Scalar -> Point -> Point
pointMul scalar p = withNewPoint $ \dx dy ->
    withScalar scalar $ \n -> withPoint p $ \px py ->
        undefined
        --ccryptonite_p256_point_mul n dx dy px py

-- | multiply the point @p with @n2 and add a lifted to curve value @n1
--
-- > n1 * G + n2 * p
pointsMulVarTime :: Scalar -> Scalar -> Point -> Point
pointsMulVarTime n1 n2 p = withNewPoint $ \dx dy ->
    withScalar n1 $ \pn1 -> withScalar n2 $ \pn2 -> withPoint p $ \px py ->
        ccryptonite_p256_points_mul_vartime pn1 pn2 px py dx dy

-- | Check if a 'Point' is valid
pointIsValid :: Point -> Bool
pointIsValid p = unsafeDoIO $ withPoint p $ \px py -> do
    r <- ccryptonite_p256_is_valid_point px py
    return (r /= 0)

------------------------------------------------------------------------
-- Scalar methods
------------------------------------------------------------------------

-- | The scalar representing 0
scalarZero :: Scalar
scalarZero = withNewScalarFreeze $ \d -> ccryptonite_p256_init d

-- | Perform addition between two scalars
--
-- > a + b
scalarAdd :: Scalar -> Scalar -> Scalar
scalarAdd a b =
    withNewScalarFreeze $ \d -> withScalar a $ \pa -> withScalar b $ \pb -> do
        void $ ccryptonite_p256_add pa pb d
        ccryptonite_p256_mod ccryptonite_SECP256r1_n d d

-- | Perform subtraction between two scalars
--
-- > a - b
scalarSub :: Scalar -> Scalar -> Scalar
scalarSub a b =
    withNewScalarFreeze $ \d -> withScalar a $ \pa -> withScalar b $ \pb -> do
        void $ ccryptonite_p256_sub pa pb d
        ccryptonite_p256_mod ccryptonite_SECP256r1_n d d

-- | Give the inverse of the scalar
--
-- > 1 / a
scalarInv :: Scalar -> Scalar
scalarInv a =
    withNewScalarFreeze $ \b -> withScalar a $ \pa ->
        undefined
        --ccryptonite_p256_modinv ccryptonite_SECP256r1_n pa b

-- | similar to 'scalarInv' but instead of
-- trying to be constant time, do it as fast as possible
scalarInvVarTime :: Scalar -> Scalar
scalarInvVarTime a =
    withNewScalarFreeze $ \b -> withScalar a $ \pa ->
        ccryptonite_p256_modinv_vartime ccryptonite_SECP256r1_n pa b

-- | Compare 2 Scalar
scalarCmp :: Scalar -> Scalar -> Ordering
scalarCmp a b = unsafeDoIO $
    withScalar a $ \pa -> withScalar b $ \pb -> do
        v <- ccryptonite_p256_cmp pa pb
        return $ compare v 0

-- | convert a scalar from binary
scalarFromBinary :: ByteArrayAccess ba => ba -> CryptoFailable Scalar
scalarFromBinary ba
    | B.length ba /= scalarSize = CryptoFailed $ CryptoError_SecretKeySizeInvalid
    | otherwise                 =
        CryptoPassed $ withNewScalarFreeze $ \p -> B.withByteArray ba $ \b ->
            ccryptonite_p256_from_bin b p

-- | convert a scalar to binary
scalarToBinary :: ByteArray ba => Scalar -> ba
scalarToBinary s = B.allocAndFreeze scalarSize $ \b -> withScalar s $ \p ->
    undefined
    --ccryptonite_p256_to_bin p b

------------------------------------------------------------------------
-- Memory Helpers
------------------------------------------------------------------------
withNewPoint :: (Ptr P256X -> Ptr P256Y -> IO ()) -> Point
withNewPoint f = unsafeDoIO $ do
    (x,y) <- B.allocRet pointCoordSize $ \py -> B.alloc pointCoordSize $ \px -> f px py
    return $! Point x y
  where pointCoordSize = 32
{-# NOINLINE withNewPoint #-}

withPoint :: Point -> (Ptr P256X -> Ptr P256Y -> IO a) -> IO a
withPoint (Point x y) f = B.withByteArray x $ \px -> B.withByteArray y $ \py -> f px py

withNewScalarFreeze :: (Ptr P256Scalar -> IO ()) -> Scalar
withNewScalarFreeze f = Scalar $ B.allocAndFreeze scalarSize f
{-# NOINLINE withNewScalarFreeze #-}

withScalar :: Scalar -> (Ptr P256Scalar -> IO a) -> IO a
withScalar (Scalar d) f = B.withByteArray d f

------------------------------------------------------------------------
-- Foreign bindings
------------------------------------------------------------------------
foreign import ccall "&cryptonite_SECP256r1_n"
    ccryptonite_SECP256r1_n :: Ptr P256Scalar
foreign import ccall "&cryptonite_SECP256r1_p"
    ccryptonite_SECP256r1_p :: Ptr P256Scalar
foreign import ccall "&cryptonite_SECP256r1_b"
    ccryptonite_SECP256r1_b :: Ptr P256Scalar

foreign import ccall "cryptonite_p256_init"
    ccryptonite_p256_init :: Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_clear"
    ccryptonite_p256_clear :: Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_add"
    ccryptonite_p256_add :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO CInt
foreign import ccall "cryptonite_p256_sub"
    ccryptonite_p256_sub :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO CInt
foreign import ccall "cryptonite_p256_cmp"
    ccryptonite_p256_cmp :: Ptr P256Scalar -> Ptr P256Scalar -> IO CInt
foreign import ccall "cryptonite_p256_mod"
    ccryptonite_p256_mod :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_modmul"
    ccryptonite_p256_modmul :: Ptr P256Scalar -> Ptr P256Scalar -> P256Digit -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
--foreign import ccall "cryptonite_p256_modinv"
--    ccryptonite_p256_modinv :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_modinv_vartime"
    ccryptonite_p256_modinv_vartime :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_base_point_mul"
    ccryptonite_p256_basepoint_mul :: Ptr P256Scalar
                                   -> Ptr P256X -> Ptr P256Y
                                   -> IO ()

foreign import ccall "cryptonite_p256e_point_add"
    ccryptonite_p256e_point_add :: Ptr P256X -> Ptr P256Y
                                -> Ptr P256X -> Ptr P256Y
                                -> Ptr P256X -> Ptr P256Y
                                -> IO ()
--foreign import ccall "cryptonite_p256_point_mul"
--    ccryptonite_p256_point_mul :: Ptr P256Scalar
--                               -> Ptr P256X -> Ptr P256Y
--                               -> Ptr P256X -> Ptr P256Y
--                               -> IO ()
foreign import ccall "cryptonite_p256_points_mul_vartime"
    ccryptonite_p256_points_mul_vartime :: Ptr P256Scalar -> Ptr P256Scalar
                                        -> Ptr P256X -> Ptr P256Y
                                        -> Ptr P256X -> Ptr P256Y
                                        -> IO ()
foreign import ccall "cryptonite_p256_is_valid_point"
    ccryptonite_p256_is_valid_point :: Ptr P256X -> Ptr P256Y -> IO CInt

--foreign import ccall "cryptonite_p256_to_bin"
--    ccryptonite_p256_to_bin :: Ptr P256Scalar -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_p256_from_bin"
    ccryptonite_p256_from_bin :: Ptr Word8 -> Ptr P256Scalar -> IO ()
