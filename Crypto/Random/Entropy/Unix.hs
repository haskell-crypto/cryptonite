-- |
-- Module      : Crypto.Random.Entropy.Unix
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Random.Entropy.Unix
    ( DevRandom
    , DevURandom
    ) where

import Foreign.Ptr
import Data.Word (Word8)
import Crypto.Random.Entropy.Source
import Control.Exception as E

import System.Posix.Types (Fd)
import System.Posix.IO

type H = Fd
type DeviceName = String

-- | Entropy device /dev/random on unix system 
newtype DevRandom  = DevRandom DeviceName

-- | Entropy device /dev/urandom on unix system 
newtype DevURandom = DevURandom DeviceName

instance EntropySource DevRandom where
    entropyOpen = fmap DevRandom `fmap` testOpen "/dev/random"
    entropyGather (DevRandom name) ptr n =
        withDev name $ \h -> gatherDevEntropy h ptr n
    entropyClose (DevRandom _)  = return ()

instance EntropySource DevURandom where
    entropyOpen = fmap DevURandom `fmap` testOpen "/dev/urandom"
    entropyGather (DevURandom name) ptr n =
        withDev name $ \h -> gatherDevEntropy h ptr n
    entropyClose (DevURandom _)  = return ()

testOpen :: DeviceName -> IO (Maybe DeviceName)
testOpen filepath = do
    d <- openDev filepath
    case d of
        Nothing -> return Nothing
        Just h  -> closeDev h >> return (Just filepath)

openDev :: String -> IO (Maybe H)
openDev filepath = (Just `fmap` openFd filepath ReadOnly Nothing fileFlags)
    `E.catch` \(_ :: IOException) -> return Nothing
  where fileFlags = defaultFileFlags { nonBlock = True }

withDev :: String -> (H -> IO a) -> IO a
withDev filepath f = openDev filepath >>= \h ->
    case h of
        Nothing -> error ("device " ++ filepath ++ " cannot be grabbed")
        Just fd -> f fd >>= \r -> (closeDev fd >> return r)

closeDev :: H -> IO ()
closeDev h = closeFd h

gatherDevEntropy :: H -> Ptr Word8 -> Int -> IO Int
gatherDevEntropy h ptr sz =
     (fromIntegral `fmap` fdReadBuf h ptr (fromIntegral sz))
    `E.catch` \(_ :: IOException) -> return 0
