-- | /WARNING:/ Signature operations may leak the private key. Signature verification
-- should be safe.
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.PubKey.ECC.ECDSA
    ( Signature(..)
    , PublicPoint
    , PublicKey(..)
    , PrivateNumber
    , PrivateKey(..)
    , KeyPair(..)
    , toPublicKey
    , toPrivateKey
    , signWithDigest
    , signWith
    , signDigest
    , sign
    , verify
    , verifyDigest
    ) where

import Control.Monad
import Crypto.Random.Types
import Data.Bits (shiftR)
import Crypto.Internal.ByteArray (ByteArrayAccess)
import Data.Data
import Crypto.Number.Basic (numBits)
import Crypto.Number.ModArithmetic (inverse)
import Crypto.Number.Serialize
import Crypto.Number.Generate
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Prim
import Crypto.Hash
import Crypto.Hash.Types (hashDigestSize)

-- | Represent a ECDSA signature namely R and S.
data Signature = Signature
    { sign_r :: Integer -- ^ ECDSA r
    , sign_s :: Integer -- ^ ECDSA s
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Private Key.
data PrivateKey = PrivateKey
    { private_curve :: Curve
    , private_d     :: PrivateNumber
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Public Key.
data PublicKey = PublicKey
    { public_curve :: Curve
    , public_q     :: PublicPoint
    } deriving (Show,Read,Eq,Data,Typeable)

-- | ECDSA Key Pair.
data KeyPair = KeyPair Curve PublicPoint PrivateNumber
    deriving (Show,Read,Eq,Data,Typeable)

-- | Public key of a ECDSA Key pair.
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair curve pub _) = PublicKey curve pub

-- | Private key of a ECDSA Key pair.
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair curve _ priv) = PrivateKey curve priv

-- | Sign digest using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signWithDigest :: HashAlgorithm hash
         => Integer     -- ^ k random number
         -> PrivateKey  -- ^ private key
         -> hash        -- ^ hash function
         -> Digest hash -- ^ digest to sign
         -> Maybe Signature
signWithDigest k (PrivateKey curve d) hashAlg digest = do
    let z = tHashDigest hashAlg digest n
        CurveCommon _ _ g n _ = common_curve curve
    let point = pointMul curve k g
    r <- case point of
              PointO    -> Nothing
              Point x _ -> return $ x `mod` n
    kInv <- inverse k n
    let s = kInv * (z + r * d) `mod` n
    when (r == 0 || s == 0) Nothing
    return $ Signature r s

-- | Sign message using the private key and an explicit k number.
--
-- /WARNING:/ Vulnerable to timing attacks.
signWith :: (ByteArrayAccess msg, HashAlgorithm hash)
         => Integer    -- ^ k random number
         -> PrivateKey -- ^ private key
         -> hash       -- ^ hash function
         -> msg        -- ^ message to sign
         -> Maybe Signature
signWith k pk hashAlg msg = signWithDigest k pk hashAlg (hashWith hashAlg msg)

-- | Sign digst using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
signDigest :: (HashAlgorithm hash, MonadRandom m)
     => PrivateKey -> hash -> Digest hash -> m Signature
signDigest pk hashAlg digest = do
    k <- generateBetween 1 (n - 1)
    case signWithDigest k pk hashAlg digest of
         Nothing  -> signDigest pk hashAlg digest
         Just sig -> return sig
  where n = ecc_n . common_curve $ private_curve pk

-- | Sign message using the private key.
--
-- /WARNING:/ Vulnerable to timing attacks.
sign :: (ByteArrayAccess msg, HashAlgorithm hash, MonadRandom m)
     => PrivateKey -> hash -> msg -> m Signature
sign pk hashAlg msg = signDigest pk hashAlg (hashWith hashAlg msg)

-- | Verify a digest using the public key.
verifyDigest :: HashAlgorithm hash => hash -> PublicKey -> Signature -> Digest hash -> Bool
verifyDigest _       (PublicKey _ PointO) _ _ = False
verifyDigest hashAlg pk@(PublicKey curve q) (Signature r s) digest
    | r < 1 || r >= n || s < 1 || s >= n = False
    | otherwise = maybe False (r ==) $ do
        w <- inverse s n
        let z  = tHashDigest hashAlg digest n
            u1 = z * w `mod` n
            u2 = r * w `mod` n
            x  = pointAddTwoMuls curve u1 g u2 q
        case x of
             PointO     -> Nothing
             Point x1 _ -> return $ x1 `mod` n
  where n = ecc_n cc
        g = ecc_g cc
        cc = common_curve $ public_curve pk

-- | Verify a bytestring using the public key.
verify :: (ByteArrayAccess msg, HashAlgorithm hash) => hash -> PublicKey -> Signature -> msg -> Bool
verify hashAlg pk sig msg = verifyDigest hashAlg pk sig (hashWith hashAlg msg)

-- | Truncate and hash.
tHashDigest :: HashAlgorithm hash => hash -> Digest hash -> Integer -> Integer
tHashDigest hashAlg digest n
    | d > 0 = shiftR e d
    | otherwise = e
  where e = os2ip digest
        d = hashDigestSize hashAlg * 8 - numBits n
