-- |
-- Module      : Crypto.KDF.Scrypt
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Scrypt key derivation function as defined in Colin Percival's paper "Stronger Key Derivation via Sequential Memory-Hard Functions" <http://www.tarsnap.com/scrypt/scrypt.pdf>.
--
{-# LANGUAGE BangPatterns #-}
module Crypto.KDF.Scrypt
    ( Parameters(..)
    , generate
    ) where

import Data.Word
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B (unsafeCreate, memset)
import Data.Byteable
import Foreign.Storable
import Foreign.Ptr (Ptr, plusPtr)
import Control.Applicative
import Control.Monad (forM_, void)

import qualified Crypto.KDF.PBKDF2 as PBKDF2

-- | Parameters for Scrypt
data Parameters = Parameters
    { password     :: ByteString -- ^ Password (bytes encoded)
    , salt         :: ByteString -- ^ Salt (bytes encoded)
    , n            :: Int        -- ^ Cpu/Memory cost ratio. must be a power of 2 greater than 1
    , r            :: Int        -- ^ Must satisfy r * p < 2^30
    , p            :: Int        -- ^ Must satisfy r * p < 2^30
    , outputLength :: Int        -- ^ the number of bytes to generate out of Scrypt
    }

-- | Generate the scrypt key derivation data
generate :: Parameters -> B.ByteString
generate params = undefined
