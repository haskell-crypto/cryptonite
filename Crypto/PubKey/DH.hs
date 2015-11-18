-- |
-- Module      : Crypto.PubKey.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PubKey.DH
    ( Params(..)
    , PublicNumber(..)
    , PrivateNumber(..)
    , SharedKey(..)
    , generateParams
    , generatePrivate
    , calculatePublic
    , generatePublic
    , getShared
    ) where

import Crypto.Internal.Imports
import Crypto.Number.ModArithmetic (expSafe)
import Crypto.Number.Prime (generateSafePrime)
import Crypto.Number.Generate (generateMax)
import Crypto.Random.Types
import Data.Data

-- | Represent Diffie Hellman parameters namely P (prime), and G (generator).
data Params = Params
    { params_p :: Integer
    , params_g :: Integer
    } deriving (Show,Read,Eq,Data,Typeable)

-- | Represent Diffie Hellman public number Y.
newtype PublicNumber = PublicNumber Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman private number X.
newtype PrivateNumber = PrivateNumber Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | Represent Diffie Hellman shared secret.
newtype SharedKey = SharedKey Integer
    deriving (Show,Read,Eq,Enum,Real,Num,Ord)

-- | generate params from a specific generator (2 or 5 are common values)
-- we generate a safe prime (a prime number of the form 2p+1 where p is also prime)
generateParams :: MonadRandom m =>
                  Int                   -- ^ number of bits
               -> Integer               -- ^ generator
               -> m Params
generateParams bits generator =
    (\p -> Params p generator) <$> generateSafePrime bits

-- | generate a private number with no specific property
-- this number is usually called X in DH text.
generatePrivate :: MonadRandom m => Params -> m PrivateNumber
generatePrivate (Params p _) = PrivateNumber <$> generateMax p

-- | calculate the public number from the parameters and the private key
-- this number is usually called Y in DH text.
calculatePublic :: Params -> PrivateNumber -> PublicNumber
calculatePublic (Params p g) (PrivateNumber x) = PublicNumber $ expSafe g x p

-- | calculate the public number from the parameters and the private key
-- this number is usually called Y in DH text.
--
-- DEPRECATED use calculatePublic
generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic = calculatePublic
-- commented until 0.3 {-# DEPRECATED generatePublic "use calculatePublic" #-}

-- | generate a shared key using our private number and the other party public number
getShared :: Params -> PrivateNumber -> PublicNumber -> SharedKey
getShared (Params p _) (PrivateNumber x) (PublicNumber y) = SharedKey $ expSafe y x p
