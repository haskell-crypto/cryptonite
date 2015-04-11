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

import Crypto.Internal.ByteArray

chunk :: ByteArray b => Int -> b -> [b]
chunk sz bs = split bs
  where split b | byteArrayLength b <= sz = [b]
                | otherwise        =
                        let (b1, b2) = byteArraySplit sz b
                         in b1 : split b2
