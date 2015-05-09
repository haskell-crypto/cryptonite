-- |
-- Module      : Data.Memory.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE NoImplicitPrelude #-}
module Data.Memory.ByteArray
    ( module X
    ) where

import           Data.Memory.ByteArray.Types         as X
import           Data.Memory.ByteArray.Methods       as X
import           Data.Memory.ByteArray.ScrubbedBytes as X (ScrubbedBytes)
import           Data.Memory.ByteArray.Bytes         as X (Bytes)
import           Data.Memory.ByteArray.MemView       as X (MemView(..))
