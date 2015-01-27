-- |
-- Module      : Crypto.Internal.Compat
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- This module try to keep all the difference between versions of base
-- or other needed packages, so that modules don't need to use CPP
--
{-# LANGUAGE CPP #-}
module Crypto.Internal.Compat
    ( unsafeDoIO
    ) where

import System.IO.Unsafe

-- | perform io for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
unsafeDoIO :: IO a -> a
#if __GLASGOW_HASKELL__ > 704
unsafeDoIO = unsafeDupablePerformIO
#else
unsafeDoIO = unsafePerformIO
#endif
