-- |
-- Module      : Crypto.Random.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Random.Types
    ( Random(..)
    ) where

import Data.Byteable
import Data.SecureMem

newtype Random = Random SecureMem
    deriving (Eq, Byteable)
