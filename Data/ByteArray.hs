-- |
-- Module      : Data.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
--
-- This module should be imported qualified.
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE NoImplicitPrelude #-}
module Data.ByteArray
    ( module X
    ) where

import           Data.ByteArray.Types         as X
import           Data.ByteArray.Methods       as X
import           Data.ByteArray.ScrubbedBytes as X (ScrubbedBytes)
import           Data.ByteArray.Bytes         as X (Bytes)
import           Data.ByteArray.MemView       as X (MemView(..))
