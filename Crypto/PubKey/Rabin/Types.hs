-- |
-- Module      : Crypto.PubKey.Rabin.Types
-- License     : BSD-style
-- Maintainer  : Carlos Rodriguez-Vega <crodveg@yahoo.es>
-- Stability   : experimental
-- Portability : unknown
--
module Crypto.PubKey.Rabin.Types
    ( Error(..)
    , generatePrimes
    ) where

import Crypto.Number.Basic (numBits)
import Crypto.Number.Prime (generatePrime, findPrimeFromWith)
import Crypto.Random.Types

type PrimeCondition = Integer -> Bool

-- | Error possible during encryption, decryption or signing.
data Error = MessageTooLong       -- ^ The message to encrypt is too long
           | MessageNotRecognized -- ^ The message decrypted doesn't have a OAEP structure
           | InvalidParameters    -- ^ Some parameters lead to breaking assumptions
           deriving (Show, Eq)

-- | Generate primes /p/ & /q/
generatePrimes :: MonadRandom m 
               => Int                   -- ^ Size in bytes
               -> PrimeCondition        -- ^ Condition prime /p/ must satisfy
               -> PrimeCondition        -- ^ Condition prime /q/ must satisfy
               -> m (Integer, Integer)  -- ^ Chosen distinct primes /p/ and /q/
generatePrimes size pCond qCond =
    let pBits = (8*(size `div` 2))
        qBits = (8*(size - (size `div` 2)))
     in do
        p <- generatePrime' pBits pCond
        q <- generatePrime' qBits qCond
        return (p, q)
      where
        generatePrime' bits cond = do
            pr' <- generatePrime bits
            let pr = findPrimeFromWith cond pr'
            if numBits pr == bits then return pr
            else generatePrime' bits cond
