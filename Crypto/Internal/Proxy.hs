-- |
-- Module      : Crypto.Internal.Proxy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Internal.Proxy
    ( Proxy(..)
    ) where

-- | A type witness for 'a' as phantom type
data Proxy a = Proxy
