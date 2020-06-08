-- |
-- Module      : Crypto.Random.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Crypto.Random.Types
    (
      MonadRandom(..)
    , MonadPseudoRandom
    , DRG(..)
    , PRG(..)
    , newPrgFromEntropy
    , newPrg
    , withDRG
    ) where

import Crypto.Random.Entropy
import Crypto.Internal.ByteArray

-- | A monad constraint that allows to generate random bytes
class Monad m => MonadRandom m where
    getRandomBytes :: ByteArray byteArray => Int -> m byteArray

-- | A Deterministic Random Generator (DRG) class
class DRG gen where
    -- | Generate N bytes of randomness from a DRG
    randomBytesGenerate :: ByteArray byteArray => Int -> gen -> (byteArray, gen)

-- | A Psuedo Random Generator (PRG) class
--
-- Like 'DRG' but also supports initialisation from some fixed seed.
class DRG gen => PRG gen where
    -- | Initialize the DRG from some fixed seed.
    newPrgFromSeed :: ByteArrayAccess seed => seed -> gen
    -- | Length of seed in bytes
    prgSeedLength :: Int

-- | Initialize the PRG from some entropy supplier.
newPrgFromEntropy :: forall gen f. (PRG gen, Functor f)
                  => (Int -> f ScrubbedBytes)
                  -> f gen
newPrgFromEntropy myGetEntropy =
    newPrgFromSeed <$> myGetEntropy (prgSeedLength @gen)

-- | Initialize the PRG from a 'MonadRandom'.
newPrg :: (PRG gen, MonadRandom f) => f gen
newPrg = newPrgFromEntropy getRandomBytes

instance MonadRandom IO where
    getRandomBytes = getEntropy

-- | A simple Monad class very similar to a State Monad
-- with the state being a DRG.
newtype MonadPseudoRandom gen a = MonadPseudoRandom
    { runPseudoRandom :: gen -> (a, gen)
    }

instance DRG gen => Functor (MonadPseudoRandom gen) where
    fmap f m = MonadPseudoRandom $ \g1 ->
        let (a, g2) = runPseudoRandom m g1 in (f a, g2)

instance DRG gen => Applicative (MonadPseudoRandom gen) where
    pure a     = MonadPseudoRandom $ \g -> (a, g)
    (<*>) fm m = MonadPseudoRandom $ \g1 ->
        let (f, g2) = runPseudoRandom fm g1
            (a, g3) = runPseudoRandom m g2
         in (f a, g3)

instance DRG gen => Monad (MonadPseudoRandom gen) where
    return      = pure
    (>>=) m1 m2 = MonadPseudoRandom $ \g1 ->
        let (a, g2) = runPseudoRandom m1 g1
         in runPseudoRandom (m2 a) g2

instance DRG gen => MonadRandom (MonadPseudoRandom gen) where
    getRandomBytes n = MonadPseudoRandom (randomBytesGenerate n)

-- | Run a pure computation with a Deterministic Random Generator
-- in the 'MonadPseudoRandom'
withDRG :: DRG gen => gen -> MonadPseudoRandom gen a -> (a, gen)
withDRG gen m = runPseudoRandom m gen
