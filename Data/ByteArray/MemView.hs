-- |
-- Module      : Data.ByteArray.MemView
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
module Data.ByteArray.MemView
    ( MemView(..)
    ) where

import           Foreign.Ptr
import           Data.ByteArray.Types
import           Data.Memory.Internal.Imports

data MemView = MemView !(Ptr Word8) !Int

instance ByteArrayAccess MemView where
    length (MemView _ l) = l
    withByteArray (MemView p _) f = f (castPtr p)

