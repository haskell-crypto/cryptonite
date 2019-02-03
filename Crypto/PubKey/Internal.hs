-- |
-- Module      : Crypto.PubKey.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.Internal
    ( and'
    , (&&!)
    , dsaTruncHash
    ) where

import Crypto.Hash
import Crypto.Internal.ByteArray (ByteArrayAccess)
import Crypto.Number.Basic (numBits)
import Crypto.Number.Serialize
import Data.Bits (shiftR)
import Data.List (foldl')

-- | This is a strict version of and
and' :: [Bool] -> Bool
and' l = foldl' (&&!) True l

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False

-- | Truncate and hash for DSA and ECDSA.
dsaTruncHash :: (ByteArrayAccess msg, HashAlgorithm hash) => hash -> msg -> Integer -> Integer
dsaTruncHash hashAlg m n
    | d > 0 = shiftR e d
    | otherwise = e
  where e = os2ip $ hashWith hashAlg m
        d = hashDigestSize hashAlg * 8 - numBits n
