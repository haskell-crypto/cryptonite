module Crypto.Random.Entropy.GetRandom (GetRandom(..)) where

import Foreign.Ptr (Ptr)
import Foreign.C.Types (CSize(..), CUInt(..))
import Foreign.C.Error (throwErrnoIf)
import Data.Word (Word8)
import Crypto.Random.Entropy.Source

foreign import ccall unsafe "getrandom"
  c_getrandom :: Ptr Word8 -> CSize -> CUInt -> IO CSize

data GetRandom = GetRandom

instance EntropySource GetRandom where
  entropyOpen     = return $ Just GetRandom
  entropyGather _ = getRandomBytes
  entropyClose _  = return ()

getRandomBytes :: Ptr Word8 -> Int -> IO Int
getRandomBytes ptr sz = 
      throwErrnoIf (< 0) "getrandom()"
  $   fromIntegral
  <$> c_getrandom ptr (fromIntegral sz) 0

