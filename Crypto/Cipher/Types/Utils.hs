-- |
-- Module      : Crypto.Cipher.Types.Utils
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- basic utility for cipher related stuff
--
module Crypto.Cipher.Types.Utils where

import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

chunk :: Int -> ByteString -> [ByteString]
chunk sz bs = split bs
  where split b | B.length b <= sz = [b]
                | otherwise        =
                        let (b1, b2) = B.splitAt sz b
                         in b1 : split b2

bxor :: ByteString -> ByteString -> ByteString
bxor src dst = B.pack $ B.zipWith xor src dst
