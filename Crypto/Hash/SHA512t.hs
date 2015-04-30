-- |
-- Module      : Crypto.Hash.SHA512t
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA512/t
--
module Crypto.Hash.SHA512t
    (--  Ctx(..)

    -- * Incremental hashing Functions
      init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    --, hash     -- :: ByteString -> ByteString
    --, hashlazy -- :: ByteString -> ByteString
    ) where

import           Prelude hiding (init, take)
import           Data.List (foldl')
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.SHA512 as SHA512
import           Crypto.Internal.Compat
import           Crypto.Internal.ByteArray (ByteArray, ByteArrayAccess, take)
--import qualified Crypto.Hash.Internal.SHA512t as SHA512t
--import           Crypto.Hash.Internal.SHA512 (withCtxNew)

init = undefined
update = undefined
finalize = undefined
{-
-- | SHA512 Context with variable size output
data Ctx = Ctx !Int !SHA512.Ctx

-- | init a context
init :: Int -> Ctx
init t = Ctx t $ unsafeDoIO $ withCtxNew $ \ptr -> SHA512t.internalInitAt t ptr

-- | update a context with a bytestring
update :: ByteArrayAccess ba => Ctx -> ba -> Ctx
update (Ctx t ctx) d = Ctx t (SHA512.update ctx d)

-- | finalize the context into a digest bytestring
finalize :: ByteArray digest => Ctx -> digest
finalize (Ctx sz ctx) = take (sz `div` 8) (SHA512.finalize ctx)

-- | hash a strict bytestring into a digest bytestring
hash :: (ByteArrayAccess ba, ByteArray digest) => Int -> ba -> digest
hash t = finalize . update (init t)

-- | hash a lazy bytestring into a digest bytestring
hashlazy :: ByteArray digest => Int -> L.ByteString -> digest
hashlazy t = finalize . foldl' update (init t) . L.toChunks
-}
