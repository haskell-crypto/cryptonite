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
import Data.SecureMem

import Crypto.Random.Types
import Crypto.Random.Entropy.Unsafe

-- | Get some entropy from the system source of entropy
getEntropy :: Int -> IO Random
getEntropy n = do
    backends <- catMaybes `fmap` sequence supportedBackends
    out      <- allocateSecureMem n
    withSecureMemPtr out $ replenish n backends
    return $ Random out
