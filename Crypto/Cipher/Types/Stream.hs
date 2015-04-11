-- |
-- Module      : Crypto.Cipher.Types.Stream
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- stream cipher basic types
--
module Crypto.Cipher.Types.Stream
    ( StreamCipher(..)
    ) where

import Crypto.Cipher.Types.Base
import Data.ByteString (ByteString)

-- | Symmetric stream cipher class
class Cipher cipher => StreamCipher cipher where
    -- | Combine using the stream cipher
    streamCombine :: cipher -> ByteString -> (ByteString, cipher)
