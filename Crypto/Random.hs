-- |
-- Module      : Crypto.Random
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Random
    (
    -- * Deterministic instances
      ChaChaDRG
    -- * Deterministic Random class
    , drgNew
    , drgNewTest
    , withDRG
    , withRandomBytes
    , DRG(..)
    -- * Random abstraction
    , MonadRandom(..)
    , MonadPseudoRandom
    ) where

import Crypto.Random.Types
import Crypto.Random.ChaChaDRG
import Crypto.Random.Entropy
import Data.ByteArray (ByteArray, ScrubbedBytes)
import Crypto.Internal.Imports

-- | Create a new DRG from system entropy
drgNew :: MonadRandom randomly => randomly ChaChaDRG
drgNew = do
    b <- getRandomBytes 40
    return $ initialize (b :: ScrubbedBytes)

-- | Create a new DRG from 5 Word64.
--
-- This is a convenient interface to create deterministic interface
-- for quickcheck style testing.
--
-- It can also be used in other contexts provided the input
-- has been properly randomly generated.
drgNewTest :: (Word64, Word64, Word64, Word64, Word64) -> ChaChaDRG
drgNewTest = initializeWords

-- | Generate @len random bytes and mapped the bytes to the function @f.
--
-- This is equivalent to use Control.Arrow 'first' with 'randomBytesGenerate'
withRandomBytes :: (ByteArray ba, DRG g) => g -> Int -> (ba -> a) -> (a, g)
withRandomBytes rng len f = (f bs, rng')
  where (bs, rng') = randomBytesGenerate len rng
