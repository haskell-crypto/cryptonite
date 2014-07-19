-- |
-- Module      : Crypto.Random.Entropy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Random.Entropy
    ( EntropyPool
    , createEntropyPool
    , getEntropyPtr
    , getEntropyFrom
    , getEntropy
    ) where

import Control.Concurrent.MVar
import Data.Maybe (catMaybes)
import Data.SecureMem
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (plusPtr, Ptr)

import Crypto.Random.Types

import Crypto.Random.Entropy.Source
#ifdef SUPPORT_RDRAND
import Crypto.Random.Entropy.RDRand
#endif
#ifdef WINDOWS
import Crypto.Random.Entropy.Windows
#else
import Crypto.Random.Entropy.Unix
#endif

supportedBackends :: [IO (Maybe EntropyBackend)]
supportedBackends =
    [
#ifdef SUPPORT_RDRAND
    openBackend (undefined :: RDRand),
#endif
#ifdef WINDOWS
    openBackend (undefined :: WinCryptoAPI)
#else
    openBackend (undefined :: DevRandom), openBackend (undefined :: DevURandom)
#endif
    ]

data EntropyBackend = forall b . EntropySource b => EntropyBackend b

openBackend :: EntropySource b => b -> IO (Maybe EntropyBackend)
openBackend b = fmap EntropyBackend `fmap` callOpen b
  where callOpen :: EntropySource b => b -> IO (Maybe b)
        callOpen _ = entropyOpen

gatherBackend :: EntropyBackend -> Ptr Word8 -> Int -> IO Int
gatherBackend (EntropyBackend backend) ptr n = entropyGather backend ptr n

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

-- | Get some entropy from the system source of entropy
getEntropy :: Int -> IO Random
getEntropy n = do
    backends <- catMaybes `fmap` sequence supportedBackends
    out      <- allocateSecureMem n
    withSecureMemPtr out $ replenish n backends
    return $ Random out

-- Refill the entropy in a buffer
replenish :: Int -> [EntropyBackend] -> Ptr Word8 -> IO ()
replenish _        []       _   = fail "cryptonite: random: cannot get any source of entropy on this system"
replenish poolSize backends ptr = loop 0 backends ptr poolSize
  where loop :: Int -> [EntropyBackend] -> Ptr Word8 -> Int -> IO ()
        loop retry [] p n | n == 0     = return ()
                          | retry == 3 = error "cryptonite: random: cannot fully replenish"
                          | otherwise  = loop (retry+1) backends p n
        loop _     (_:_)  _ 0 = return ()
        loop retry (b:bs) p n = do
            r <- gatherBackend b p n
            loop retry bs (p `plusPtr` r) (n - r)
