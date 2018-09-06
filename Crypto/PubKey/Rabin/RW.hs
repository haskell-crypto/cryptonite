-- |
-- Module      : Crypto.PubKey.Rabin.RW
-- License     : BSD-style
-- Maintainer  : Carlos Rodrigue-Vega <crodveg@yahoo.es>
-- Stability   : experimental
-- Portability : unknown
--
-- Rabin-Williams cryptosystem for public-key encryption and digital signature. 
-- See pages 323 - 324 in "Computational Number Theory and Modern Cryptography" by Song Y. Yan.
-- Also inspired by https://github.com/vanilala/vncrypt/blob/master/vncrypt/vnrw_gmp.c.
-- 
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.PubKey.Rabin.RW
    ( PublicKey(..)
    , PrivateKey(..)
    , generate
    , encrypt
    , decrypt
    , sign
    , verify
    ) where

import           Data.ByteString
import qualified Data.ByteString as B
import           Data.Data

import           Crypto.Hash
import           Crypto.Number.Basic (gcde)
import           Crypto.Number.ModArithmetic (expSafe, jacobi)
import           Crypto.Number.Serialize (i2osp, os2ip)
import           Crypto.PubKey.Rabin.Types
import           Crypto.Random.Types

-- | Represent a Rabin-Williams public key.
data PublicKey = PublicKey
    { public_size :: Int      -- ^ size of key in bytes
    , public_n    :: Integer  -- ^ public p*q
    } deriving (Show, Read, Eq, Data, Typeable)

-- | Represent a Rabin-Williams private key.
data PrivateKey = PrivateKey
    { private_pub :: PublicKey
    , private_p   :: Integer   -- ^ p prime number
    , private_q   :: Integer   -- ^ q prime number
    , private_d   :: Integer
    } deriving (Show, Read, Eq, Data, Typeable)

-- | Generate a pair of (private, public) key of size in bytes.
-- Prime p is congruent 3 mod 8 and prime q is congruent 7 mod 8.
generate :: MonadRandom m
         => Int           
         -> m (PublicKey, PrivateKey)
generate size = do
    (p, q) <- generatePrimes size (\p -> p `mod` 8 == 3) (\q -> q `mod` 8 == 7) 
    return (generateKeys p q)
    where 
        generateKeys p q =
            let n = p*q   
                d = ((p - 1)*(q - 1) `div` 4 + 1) `div` 2
                publicKey = PublicKey { public_size = size
                                      , public_n    = n }
                privateKey = PrivateKey { private_pub = publicKey
                                        , private_p   = p
                                        , private_q   = q
                                        , private_d   = d }
             in (publicKey, privateKey)

-- | Encrypt plaintext using public key.
encrypt :: PublicKey    -- ^ public key
        -> ByteString   -- ^ plaintext
        -> Either Error ByteString
encrypt pk m =
    let n  = public_n pk
     in case ep1 n $ os2ip m of
            Right m' -> Right $ i2osp $ ep2 n m'
            Left err -> Left err

-- | Decrypt ciphertext using private key.
decrypt :: PrivateKey   -- ^ private key
        -> ByteString   -- ^ ciphertext
        -> ByteString
decrypt pk c =
    let d  = private_d pk    
        n  = public_n $ private_pub pk 
     in i2osp $ dp2 n $ dp1 d n $ os2ip c

-- | Sign message using hash algorithm and private key.
sign :: (HashAlgorithm hash)
     => PrivateKey  -- ^ private key
     -> hash        -- ^ hash function
     -> ByteString  -- ^ message to sign
     -> Either Error ByteString
sign pk hashAlg m =
    let d  = private_d pk
        n  = public_n $ private_pub pk
     in case ep1 n $ os2ip $ hashWith hashAlg m of
            Right m' -> Right (i2osp $ dp1 d n m')
            Left err -> Left err

-- | Verify signature using hash algorithm and public key.
verify :: (HashAlgorithm hash)
       => PublicKey     -- ^ public key
       -> hash          -- ^ hash function
       -> ByteString    -- ^ message
       -> ByteString    -- ^ signature
       -> Bool
verify pk hashAlg m s =
    let n  = public_n pk
        h  = os2ip $ hashWith hashAlg m
        h' = dp2 n $ ep2 n $ os2ip s
     in h' == h

-- | Encryption primitive 1
ep1 :: Integer -> Integer -> Either Error Integer
ep1 n m =
    let m'   = 2*m + 1
        m''  = 2*m'
        m''' = 2*m''
     in case jacobi m' n of
            Just (-1) | m'' < n -> Right m''
            Just 1 | m''' < n   -> Right m'''
            _                   -> Left InvalidParameters

-- | Encryption primitive 2
ep2 :: Integer -> Integer -> Integer
ep2 n m = expSafe m 2 n

-- | Decryption primitive 1
dp1 :: Integer -> Integer -> Integer -> Integer
dp1 d n c = expSafe c d n

-- | Decryption primitive 2
dp2 :: Integer -> Integer -> Integer
dp2 n c = let c'  = c `div` 2
              c'' = (n - c) `div` 2
           in case c `mod` 4 of
                0 -> ((c' `div` 2 - 1) `div` 2)
                1 -> ((c'' `div` 2 - 1) `div` 2)
                2 -> ((c' - 1) `div` 2)
                _ -> ((c'' - 1) `div` 2)
