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
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
module Crypto.PubKey.ECC.P256
    ( Scalar
    , Point
    ) where

import           Data.Word
import           Foreign.Ptr
import           Foreign.C.Types

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Internal.Memory
import           Crypto.Internal.ByteArray
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Error

-- | A P256 scalar
newtype Scalar = Scalar SecureBytes
    deriving (Eq,ByteArrayAccess)

-- | A P256 point
data Point = Point !Bytes !Bytes
    deriving (Show,Eq)

publicKeySize :: Int
publicKeySize = 32

secretKeySize :: Int
secretKeySize = 32

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

------------------------------------------------------------------------
-- Scalar methods
------------------------------------------------------------------------

scalarZero :: Scalar
scalarZero = withNewScalarFreeze $ \d -> ccryptonite_p256_init d

scalarAdd :: Scalar -> Scalar -> Scalar
scalarAdd a b =
    withNewScalarFreeze $ \d -> withScalar a $ \pa -> withScalar b $ \pb ->
        void $ ccryptonite_p256_add pa pb d

scalarSub :: Scalar -> Scalar -> Scalar
scalarSub a b =
    withNewScalarFreeze $ \d -> withScalar a $ \pa -> withScalar b $ \pb ->
        void $ ccryptonite_p256_sub pa pb d

scalarCmp :: Scalar -> Scalar -> Ordering
scalarCmp a b = unsafeDoIO $
    withScalar a $ \pa -> withScalar b $ \pb -> do
        v <- ccryptonite_p256_cmp pa pb
        return $ compare v 0

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
  where scalarSize = 32
{-# NOINLINE withNewScalarFreeze #-}

withScalar :: Scalar -> (Ptr P256Scalar -> IO a) -> IO a
withScalar (Scalar d) f = B.withByteArray d f

------------------------------------------------------------------------
-- Foreign bindings
------------------------------------------------------------------------

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
foreign import ccall "cryptonite_p256_modinv"
    ccryptonite_p256_modinv :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_modinv_vartime"
    ccryptonite_p256_modinv_vartime :: Ptr P256Scalar -> Ptr P256Scalar -> Ptr P256Scalar -> IO ()
foreign import ccall "cryptonite_p256_base_point_mul"
    ccryptonite_p256_basepoint_mul :: Ptr P256Scalar
                                   -> Ptr P256X -> Ptr P256Y
                                   -> IO ()
foreign import ccall "cryptonite_p256_point_mul"
    ccryptonite_p256_point_mul :: Ptr P256Scalar
                               -> Ptr P256Scalar -> Ptr P256Scalar
                               -> Ptr P256Scalar -> Ptr P256Scalar
                               -> IO ()
foreign import ccall "cryptonite_p256_is_valid_point"
    ccryptonite_p256_is_valid_point :: Ptr P256Scalar -> Ptr P256Scalar -> IO CInt

foreign import ccall "cryptonite_p256_to_bin"
    ccryptonite_p256_to_bin :: Ptr P256Scalar -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_p256_from_bin"
    ccryptonite_p256_from_bin :: Ptr Word8 -> Ptr P256Scalar -> IO ()
