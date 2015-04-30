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
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.Hash (hashWith, HashAlgorithm)
import qualified Crypto.Internal.ByteArray as B (convert)

-- | Represent a mask generation algorithm
type MaskGenAlgorithm =
       ByteString -- ^ seed
    -> Int        -- ^ length to generate
    -> ByteString

-- | Mask generation algorithm MGF1
mgf1 :: HashAlgorithm hashAlg => hashAlg -> MaskGenAlgorithm
mgf1 hashAlg seed len = loop B.empty 0
    where loop t counter
            | B.length t >= len = B.take len t
            | otherwise         = let counterBS = i2ospOf_ 4 counter
                                      newT = t `B.append` B.convert (hashWith hashAlg (seed `B.append` counterBS))
                                   in loop newT (counter+1)
