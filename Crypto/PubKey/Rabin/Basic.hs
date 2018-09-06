-- |
-- Module      : Crypto.PubKey.Rabin.Basic
-- License     : BSD-style
-- Maintainer  : Carlos Rodrigue-Vega <crodveg@yahoo.es>
-- Stability   : experimental
-- Portability : unknown
--
-- Rabin cryptosystem for public-key cryptography and digital signature.
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.PubKey.Rabin.Basic
    ( PublicKey(..)
    , PrivateKey(..)
    , generate
    , encrypt
    , decrypt
    , sign
    , verify
    ) where

import           System.Random (getStdGen, randomRs)

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Data

import           Crypto.Hash
import           Crypto.Number.Basic (gcde, asPowerOf2AndOdd)
import           Crypto.Number.ModArithmetic (expSafe, jacobi)
import           Crypto.Number.Prime (isProbablyPrime)
import           Crypto.Number.Serialize (i2osp, os2ip)
import           Crypto.PubKey.Rabin.Types
import           Crypto.Random (MonadRandom, getRandomBytes)

-- | Represent a Rabin public key.
data PublicKey = PublicKey
    { public_size :: Int      -- ^ size of key in bytes
    , public_n    :: Integer  -- ^ public p*q
    } deriving (Show, Read, Eq, Data, Typeable)

-- | Represent a Rabin private key.
data PrivateKey = PrivateKey
    { private_pub :: PublicKey
    , private_p   :: Integer   -- ^ p prime number
    , private_q   :: Integer   -- ^ q prime number
    , private_a   :: Integer
    , private_b   :: Integer
    } deriving (Show, Read, Eq, Data, Typeable)

-- | Rabin Signature.
data Signature = Signature (Integer, Integer)

-- | Generate a pair of (private, public) key of size in bytes.
-- Primes p and q are both congruent 3 mod 4.
--
-- See algorithm 8.11 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
generate :: MonadRandom m
         => Int           
         -> m (PublicKey, PrivateKey)
generate size = do
    (p, q) <- generatePrimes size (\p -> p `mod` 4 == 3) (\q -> q `mod` 4 == 3)
    return (generateKeys p q)
    where 
        generateKeys p q =
            let n = p*q
                (a, b, _) = gcde p q 
                publicKey = PublicKey { public_size = size
                                      , public_n    = n }
                privateKey = PrivateKey { private_pub = publicKey
                                        , private_p   = p
                                        , private_q   = q
                                        , private_a   = a
                                        , private_b   = b }
             in (publicKey, privateKey)

-- | Encrypt plaintext using public key.
--
-- See algorithm 8.11 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
encrypt :: PublicKey    -- ^ public key
        -> ByteString   -- ^ plaintext
        -> Either Error ByteString
encrypt pk m =
    let m' = os2ip m
        n  = public_n pk
     in if m' < 0 then Left InvalidParameters 
        else if m' >= n then Left MessageTooLong
        else Right $ i2osp $ expSafe m' 2 n

-- | Decrypt ciphertext using private key.
--
-- See algorithm 8.12 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
decrypt :: PrivateKey    -- ^ private key
        -> ByteString    -- ^ ciphertext
        -> (ByteString, ByteString, ByteString, ByteString)
decrypt pk c =
    let p  = private_p pk 
        q  = private_q pk     
        a  = private_a pk 
        b  = private_b pk
        n  = public_n $ private_pub pk 
        c' = os2ip c
     in mapTuple i2osp $ sqroot' c' p q a b n
       where mapTuple f (w, x, y, z) = (f w, f x, f y, f z)

-- | Sign message using hash algorithm and private key.
--
-- See https://en.wikipedia.org/wiki/Rabin_signature_algorithm.
sign :: (MonadRandom m, HashAlgorithm hash)
     => PrivateKey    -- ^ private key
     -> hash          -- ^ hash function
     -> ByteString    -- ^ message to sign
     -> m (Either Error Signature)
sign pk hashAlg m =
    let p    = private_p pk
        q    = private_q pk     
        a    = private_a pk 
        b    = private_b pk
        n    = public_n $ private_pub pk
     in do
        (padding, h) <- loop p q
        return (if h >= n then Left MessageTooLong
                else let (r, _, _, _) = sqroot' h p q a b n
                      in Right $ Signature (os2ip padding, r)) 
       where 
        loop p q = do
            padding <- getRandomBytes 8
            let h = os2ip $ hashWith hashAlg $ B.append m padding
            case (jacobi (h `mod` p) p, jacobi (h `mod` q) q)   of
                (Just 1, Just 1) -> return (padding, h)
                _                -> loop p q

-- | Verify signature using hash algorithm and public key.
--
-- See https://en.wikipedia.org/wiki/Rabin_signature_algorithm.
verify :: (HashAlgorithm hash)
       => PublicKey     -- ^ private key
       -> hash          -- ^ hash function
       -> ByteString    -- ^ message
       -> Signature     -- ^ signature
       -> Bool
verify pk hashAlg m (Signature (padding, x)) =
    let n  = public_n pk
        h  = os2ip $ hashWith hashAlg $ B.append m $ i2osp padding
        h' = expSafe x 2 n
     in h' == h

-- | Square roots modulo prime p where p is congruent 3 mod 4
-- Value a must be a quadratic residue modulo p (i.e. jacobi symbol (a/n) = 1).
--
-- See algorithm 3.36 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
sqroot :: Integer
       -> Integer   -- ^ prime p
       -> (Integer, Integer)
sqroot a p =
    let r = expSafe a ((p + 1) `div` 4) p
     in (r, -r)

-- | Square roots modulo n given its prime factors p and q (both congruent 3 mod 4)
-- Value a must be a quadratic residue of both modulo p and modulo q (i.e. jacobi symbols (a/p) = (a/q) = 1).
-- 
-- See algorithm 3.44 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
sqroot' :: Integer 
        -> Integer  -- ^ prime p
        -> Integer  -- ^ prime q
        -> Integer  -- ^ c such that c*p + d*q = 1
        -> Integer  -- ^ d such that c*p + d*q = 1
        -> Integer  -- ^ n = p*q
        -> (Integer, Integer, Integer, Integer)
sqroot' a p q c d n =
    let (r, _) = sqroot a p
        (s, _) = sqroot a q
        x      = (r*d*q + s*c*p) `mod` n
        y      = (r*d*q - s*c*p) `mod` n
     in (x, (-x) `mod` n, y, (-y) `mod` n)
