-- |
-- Module      : Crypto.Random.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Random.Types
    (
      MonadRandom(..)
    , DRG(..)
    , withDRG
    ) where

import Control.Applicative
import Crypto.Random.Entropy
import Crypto.Internal.ByteArray

class Monad m => MonadRandom m where
    getRandomBytes :: ByteArray byteArray => Int -> m byteArray

class DRG gen where
    randomBytesGenerate :: ByteArray byteArray => Int -> gen -> (byteArray, gen)

instance MonadRandom IO where
    getRandomBytes = getEntropy

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
    return a    = MonadPseudoRandom $ \g -> (a, g)
    (>>=) m1 m2 = MonadPseudoRandom $ \g1 ->
        let (a, g2) = runPseudoRandom m1 g1
         in runPseudoRandom (m2 a) g2

instance DRG gen => MonadRandom (MonadPseudoRandom gen) where
    getRandomBytes n = MonadPseudoRandom (randomBytesGenerate n)

withDRG :: DRG gen => gen -> MonadPseudoRandom gen a -> (a, gen)
withDRG gen m = runPseudoRandom m gen
