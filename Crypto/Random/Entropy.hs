-- |
-- Module      : Crypto.Random.Entropy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Random.Entropy
    ( getEntropy
    ) where

import Data.Maybe (catMaybes)
import Crypto.Internal.ByteArray

import Crypto.Random.Entropy.Unsafe

-- | Get some entropy from the system source of entropy
getEntropy :: ByteArray byteArray => Int -> IO byteArray
getEntropy n = do
    backends <- catMaybes `fmap` sequence supportedBackends
    byteArrayAlloc n (replenish n backends)
