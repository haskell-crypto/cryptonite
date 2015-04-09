-- |
-- Module      : Crypto.Internal.Words
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Extra Word size
--
module Crypto.Internal.Words
    ( Word128(..)
    ) where

import Data.Word

-- should probably use crypto large word ?
data Word128 = Word128 !Word64 !Word64 deriving (Show, Eq)
