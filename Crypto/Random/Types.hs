-- |
-- Module      : Crypto.Random.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Random.Types
    (
      MonadRandom(..)
    , MonadPseudoRandom
    , DRG(..)
    , PRG(..)
    , prgNew
    , prgFork
    , withDRG
    ) where

import Crypto.Error
import Crypto.Random.Entropy
import Crypto.Internal.ByteArray
import Data.ByteString
import Data.Proxy

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
    --
    -- The seed must be of length at least 'prgSeedLength'.
    prgNewSeed :: ByteArrayAccess seed => seed -> CryptoFailable gen
    -- | Length of seed in bytes
    prgSeedLength :: proxy gen -> Int

-- | Initialize the PRG from some entropy supplier.
prgNewEntropy :: forall gen f. (PRG gen, Functor f)
                  => (Int -> f ScrubbedBytes)
                  -> f (CryptoFailable gen)
prgNewEntropy myGetEntropy =
    prgNewSeed <$> myGetEntropy (prgSeedLength (Proxy :: Proxy gen))

-- | Initialize the PRG from a 'MonadRandom'.
prgNew :: (PRG gen, MonadRandom f) => f gen
prgNew = throwCryptoError <$> prgNewEntropy getRandomBytes

prgFork :: forall g. PRG g => g -> (g, g)
prgFork gen =
  {-
  Background: security definition of a PRG is that later values cannot be
  predicted from older values and vice versa, *unless* you know the seed or any
  of the secret states.

  Therefore, we do not need to do anything fancy like hashing the seed. In more
  detail, this algorithm is secure because:

  1. Given outputs (subsequent to generating the seed) from the old PRG, one
     cannot predict values of the new PRG, because that would require somehow
     deriving the seed (an old output) from the subsequent outputs, which would
     contradict the security definition of a PRG.

  2. Given outputs from the new PRG, one cannot predict values of the old PRG,
     because again this would require deriving the seed, then deriving the
     internal secret state of the old PRG, which would again contradict the
     security definition of a PRG.

  It *may* be theoretically possible to break the new PRG if you know the state
  of the old PRG (to reverse-engineer what the seed was), but we assume the
  caller consumes both PRGs and that they are not attacking themselves.
  -}
  let (seed, gen') = randomBytesGenerate (prgSeedLength (Proxy :: Proxy g)) gen
  in (throwCryptoError (prgNewSeed (seed :: ByteString)), gen')

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
