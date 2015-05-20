-- |
-- Module      : Crypto.Internal.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
--
{-# OPTIONS_HADDOCK hide #-}
module Crypto.Internal.ByteArray
    ( module Data.ByteArray
    , module Data.ByteArray.Mapping
    , module Data.ByteArray.Encoding
    ) where

import Data.ByteArray
import Data.ByteArray.Mapping
import Data.ByteArray.Encoding
