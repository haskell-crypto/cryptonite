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
    , DRG(..)
    -- * Random abstraction
    , MonadRandom(..)
    ) where

import Crypto.Random.Types
import Crypto.Random.ChaChaDRG
import Crypto.Random.Entropy
import Crypto.Internal.Memory

import Control.Applicative
import Data.Word (Word64)

drgNew :: IO ChaChaDRG
drgNew = initialize <$> (getEntropy 40 :: IO SecureBytes)

drgNewTest :: (Word64, Word64, Word64, Word64, Word64) -> ChaChaDRG
drgNewTest = initializeWords
