-- |
-- Module      : Crypto.ECC.Ed25519
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed25519 arithmetic primitives.
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.ECC.Ed25519
    ( Scalar
    , Point
    -- * Scalars
    , scalarGenerate
    , scalarDecodeLong
    , scalarEncode
    -- * Points
    , pointDecode
    , pointEncode
    -- * Arithmetic functions
    , toPoint
    , scalarAdd
    , scalarMul
    , pointNegate
    , pointAdd
    , pointDouble
    , pointMul
    ) where

import           Data.Bits
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr
import           Foreign.Storable

import           Crypto.Error
import           Crypto.Internal.ByteArray (ByteArrayAccess, Bytes,
                                            ScrubbedBytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Crypto.Random


scalarArraySize :: Int
scalarArraySize = 40 -- maximum [9 * 4 {- 32 bits -}, 5 * 8 {- 64 bits -}]

-- | A scalar modulo order of curve Ed25519.
newtype Scalar = Scalar ScrubbedBytes
    deriving (Show,NFData)

instance Eq Scalar where
    (Scalar s1) == (Scalar s2) = unsafeDoIO $
        withByteArray s1 $ \ps1 ->
        withByteArray s2 $ \ps2 ->
            fmap (/= 0) (ed25519_scalar_eq ps1 ps2)
    {-# NOINLINE (==) #-}

pointArraySize :: Int
pointArraySize = 160 -- maximum [4 * 10 * 4 {- 32 bits -}, 4 * 5 * 8 {- 64 bits -}]

-- | A point on curve Ed25519.
newtype Point = Point Bytes
    deriving NFData

instance Show Point where
    showsPrec d p =
        let bs = pointEncode p :: Bytes
         in showParen (d > 10) $ showString "Point "
                               . shows (B.convertToBase B.Base16 bs :: Bytes)

instance Eq Point where
    (Point p1) == (Point p2) = unsafeDoIO $
        withByteArray p1 $ \pp1 ->
        withByteArray p2 $ \pp2 ->
            fmap (/= 0) (ed25519_point_eq pp1 pp2)
    {-# NOINLINE (==) #-}

-- | Generate a random scalar.
scalarGenerate :: MonadRandom randomly => randomly Scalar
scalarGenerate = unwrap . scalarDecodeLong . clamp <$> generate
  where
    unwrap (CryptoPassed x) = x
    unwrap (CryptoFailed _) = error "scalarGenerate: assumption failed"

    generate :: MonadRandom randomly => randomly ScrubbedBytes
    generate = getRandomBytes 32

    -- Uses the same bit mask than during key-generation procedure,
    -- but without making divisible by 8.  As a consequence of modular
    -- reduction, distribution is not uniform.  But the curve order is
    -- very close to 2^252 so only a tiny fraction of the scalars have
    -- lower probability, roughly 1/(2^126) of all possible values.
    clamp :: ByteArrayAccess ba => ba -> ScrubbedBytes
    clamp bs = B.copyAndFreeze bs $ \p -> do
                   b31 <- peekElemOff p 31 :: IO Word8
                   pokeElemOff p 31 ((b31 .&. 0x7F) .|. 0x40)

-- | Serialize a scalar to binary, i.e. a 32-byte little-endian
-- number.
--
-- Format is binary compatible with 'Crypto.PubKey.Curve25519.SecretKey'
-- from module "Crypto.PubKey.Curve25519".
scalarEncode :: B.ByteArray bs => Scalar -> bs
scalarEncode (Scalar s) =
    B.allocAndFreeze 32 $ \out ->
        withByteArray s $ \ps -> ed25519_scalar_encode out ps

-- | Deserialize a little-endian number as a scalar.  Input array can
-- have any length from 0 to 64 bytes.
scalarDecodeLong :: B.ByteArrayAccess bs => bs -> CryptoFailable Scalar
scalarDecodeLong bs
    | B.length bs > 64 = CryptoFailed CryptoError_EcScalarOutOfBounds
    | otherwise        = unsafeDoIO $ withByteArray bs initialize
  where
    len = fromIntegral $ B.length bs
    initialize inp = do
        s <- B.alloc scalarArraySize $ \ps ->
                 ed25519_scalar_decode_long ps inp len
        return $ CryptoPassed (Scalar s)
{-# NOINLINE scalarDecodeLong #-}

-- | Add two scalars.
scalarAdd :: Scalar -> Scalar -> Scalar
scalarAdd (Scalar a) (Scalar b) =
    Scalar $ B.allocAndFreeze scalarArraySize $ \out ->
        withByteArray a $ \pa ->
        withByteArray b $ \pb ->
             ed25519_scalar_add out pa pb

-- | Multiply two scalars.
scalarMul :: Scalar -> Scalar -> Scalar
scalarMul (Scalar a) (Scalar b) =
    Scalar $ B.allocAndFreeze scalarArraySize $ \out ->
        withByteArray a $ \pa ->
        withByteArray b $ \pb ->
             ed25519_scalar_mul out pa pb

-- | Multiplies a scalar with the curve base point.
toPoint :: Scalar -> Point
toPoint (Scalar scalar) =
    Point $ B.allocAndFreeze pointArraySize $ \out ->
        withByteArray scalar $ \pscalar ->
            ed25519_point_base_scalarmul out pscalar

-- | Serialize a point to a 32-byte array.
--
-- Format is binary compatible with 'Crypto.PubKey.Ed25519.PublicKey'
-- from module "Crypto.PubKey.Ed25519".
pointEncode :: B.ByteArray bs => Point -> bs
pointEncode (Point p) =
    B.allocAndFreeze 32 $ \out ->
        withByteArray p $ \pp ->
             ed25519_point_encode out pp

-- | Deserialize a 32-byte array as a point, ensuring the point is
-- valid on Ed25519.
--
-- /WARNING:/ variable time
pointDecode :: B.ByteArrayAccess bs => bs -> CryptoFailable Point
pointDecode bs
    | B.length bs == 32 = unsafeDoIO $ withByteArray bs initialize
    | otherwise         = CryptoFailed CryptoError_PointSizeInvalid
  where
    initialize inp = do
        (res, p) <- B.allocRet pointArraySize $ \pp ->
                        ed25519_point_decode_vartime pp inp
        if res == 0 then return $ CryptoFailed CryptoError_PointCoordinatesInvalid
                    else return $ CryptoPassed (Point p)
{-# NOINLINE pointDecode #-}

-- | Negate a point.
pointNegate :: Point -> Point
pointNegate (Point a) =
    Point $ B.allocAndFreeze pointArraySize $ \out ->
        withByteArray a $ \pa ->
             ed25519_point_negate out pa

-- | Add two points.
pointAdd :: Point -> Point -> Point
pointAdd (Point a) (Point b) =
    Point $ B.allocAndFreeze pointArraySize $ \out ->
        withByteArray a $ \pa ->
        withByteArray b $ \pb ->
             ed25519_point_add out pa pb

-- | Add a point to itself.
--
-- @
-- pointDouble p = 'pointAdd' p p
-- @
pointDouble :: Point -> Point
pointDouble (Point a) =
    Point $ B.allocAndFreeze pointArraySize $ \out ->
        withByteArray a $ \pa ->
             ed25519_point_double out pa

-- | Scalar multiplication over Ed25519.
pointMul :: Scalar -> Point -> Point
pointMul (Scalar scalar) (Point base) =
    Point $ B.allocAndFreeze pointArraySize $ \out ->
        withByteArray scalar $ \pscalar ->
        withByteArray base   $ \pbase   ->
             ed25519_point_scalarmul out pbase pscalar

foreign import ccall "cryptonite_ed25519_scalar_eq"
    ed25519_scalar_eq :: Ptr Scalar
                      -> Ptr Scalar
                      -> IO CInt

foreign import ccall "cryptonite_ed25519_scalar_encode"
    ed25519_scalar_encode :: Ptr Word8
                          -> Ptr Scalar
                          -> IO ()

foreign import ccall "cryptonite_ed25519_scalar_decode_long"
    ed25519_scalar_decode_long :: Ptr Scalar
                               -> Ptr Word8
                               -> CSize
                               -> IO ()

foreign import ccall "cryptonite_ed25519_scalar_add"
    ed25519_scalar_add :: Ptr Scalar -- sum
                       -> Ptr Scalar -- a
                       -> Ptr Scalar -- b
                       -> IO ()

foreign import ccall "cryptonite_ed25519_scalar_mul"
    ed25519_scalar_mul :: Ptr Scalar -- out
                       -> Ptr Scalar -- a
                       -> Ptr Scalar -- b
                       -> IO ()

foreign import ccall "cryptonite_ed25519_point_encode"
    ed25519_point_encode :: Ptr Word8
                         -> Ptr Point
                         -> IO ()

foreign import ccall "cryptonite_ed25519_point_decode_vartime"
    ed25519_point_decode_vartime :: Ptr Point
                                 -> Ptr Word8
                                 -> IO CInt

foreign import ccall "cryptonite_ed25519_point_eq"
    ed25519_point_eq :: Ptr Point
                     -> Ptr Point
                     -> IO CInt

foreign import ccall "cryptonite_ed25519_point_negate"
    ed25519_point_negate :: Ptr Point -- minus_a
                         -> Ptr Point -- a
                         -> IO ()

foreign import ccall "cryptonite_ed25519_point_add"
    ed25519_point_add :: Ptr Point -- sum
                      -> Ptr Point -- a
                      -> Ptr Point -- b
                      -> IO ()

foreign import ccall "cryptonite_ed25519_point_double"
    ed25519_point_double :: Ptr Point -- two_a
                         -> Ptr Point -- a
                         -> IO ()

foreign import ccall "cryptonite_ed25519_point_base_scalarmul"
    ed25519_point_base_scalarmul :: Ptr Point  -- scaled
                                 -> Ptr Scalar -- scalar
                                 -> IO ()

foreign import ccall "cryptonite_ed25519_point_scalarmul"
    ed25519_point_scalarmul :: Ptr Point  -- scaled
                            -> Ptr Point  -- base
                            -> Ptr Scalar -- scalar
                            -> IO ()
