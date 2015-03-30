-- |
-- Module      : Crypto.PubKey.MaskGenFunction
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.MaskGenFunction
    ( MaskGenAlgorithm
    , mgf1
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.PubKey.HashDescr
import Crypto.Number.Serialize (i2ospOf_)

-- | Represent a mask generation algorithm
type MaskGenAlgorithm = HashFunction -- ^ hash function to use
                     -> ByteString   -- ^ seed
                     -> Int          -- ^ length to generate
                     -> ByteString

-- | Mask generation algorithm MGF1
mgf1 :: MaskGenAlgorithm
mgf1 hashF seed len = loop B.empty 0
    where loop t counter
            | B.length t >= len = B.take len t
            | otherwise         = let counterBS = i2ospOf_ 4 counter
                                      newT = t `B.append` hashF (seed `B.append` counterBS)
                                   in loop newT (counter+1)
