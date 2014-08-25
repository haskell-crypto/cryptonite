{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Random.Entropy.Backend
    ( EntropyBackend
    , supportedBackends
    , gatherBackend
    ) where

import Foreign.Ptr
import Data.Word (Word8)
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
