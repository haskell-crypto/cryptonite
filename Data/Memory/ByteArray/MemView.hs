-- |
-- Module      : Data.Memory.ByteArray.MemView
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
module Data.Memory.ByteArray.MemView
    ( MemView(..)
    ) where

import           Foreign.Ptr
import           Data.Memory.ByteArray.Types
import           Data.Memory.Internal.Imports

data MemView = MemView !(Ptr Word8) !Int

instance ByteArrayAccess MemView where
    length (MemView _ l) = l
    withByteArray (MemView p _) f = f (castPtr p)

