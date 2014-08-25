-- |
-- Module      : Crypto.Random.EntropyPool
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Random.EntropyPool
    ( EntropyPool
    , createEntropyPool
    , createEntropyPoolWith
    , getEntropyFrom
    ) where

import Control.Concurrent.MVar
import Crypto.Random.Entropy.Unsafe
import Crypto.Random.Types
import Data.SecureMem
import Data.Word (Word8)
import Data.Maybe (catMaybes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (plusPtr, Ptr)

-- | Pool of Entropy. contains a self mutating pool of entropy,
-- that is always guarantee to contains data.
data EntropyPool = EntropyPool [EntropyBackend] (MVar Int) SecureMem

-- size of entropy pool by default
defaultPoolSize :: Int
defaultPoolSize = 4096

-- | Create a new entropy pool of a specific size
--
-- While you can create as many entropy pool as you want, the pool can be shared between multiples RNGs.
createEntropyPoolWith :: Int -> [EntropyBackend] -> IO EntropyPool
createEntropyPoolWith poolSize backends = do
    sm <- allocateSecureMem poolSize
    m  <- newMVar 0
    withSecureMemPtr sm $ replenish poolSize backends
    return $ EntropyPool backends m sm

-- | Create a new entropy pool with a default size.
--
-- While you can create as many entropy pool as you want, the pool can be shared between multiples RNGs.
createEntropyPool :: IO EntropyPool
createEntropyPool = do
    backends <- catMaybes `fmap` sequence supportedBackends
    createEntropyPoolWith defaultPoolSize backends

-- | Put a chunk of the entropy pool into a buffer
getEntropyPtr :: EntropyPool -> Int -> Ptr Word8 -> IO ()
getEntropyPtr (EntropyPool backends posM sm) n outPtr =
    withSecureMemPtr sm $ \entropyPoolPtr ->
        modifyMVar_ posM $ \pos ->
            copyLoop outPtr entropyPoolPtr pos n
  where poolSize = secureMemGetSize sm
        copyLoop d s pos left
            | left == 0 = return pos
            | otherwise = do
                wrappedPos <-
                    if pos == poolSize
                        then replenish poolSize backends s >> return 0
                        else return pos
                let m = min (poolSize - wrappedPos) left
                copyBytes d (s `plusPtr` wrappedPos) m
                copyLoop (d `plusPtr` m) s (wrappedPos + m) (left - m)

-- | Grab a chunk of entropy from the entropy pool.
getEntropyFrom :: EntropyPool -> Int -> IO Random
getEntropyFrom pool n = do
    out <- allocateSecureMem n
    withSecureMemPtr out $ getEntropyPtr pool n
    return $ Random out
