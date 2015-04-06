-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- symmetric cipher basic types
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , StreamCipher(..)
    , DataUnitOffset
    , KeySizeSpecifier(..)
    , KeyError(..)
    , AEAD(..)
    , AEADState(..)
    , AEADMode(..)
    , AEADModeImpl(..)
    , cfb8Encrypt
    , cfb8Decrypt
    -- * AEAD functions
    , module Crypto.Cipher.Types.AEAD
    -- * Key type and constructor
    , Key
    , makeKey
    -- * Initial Vector type and constructor
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Data.SecureMem
import Data.Byteable
import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block
import Crypto.Cipher.Types.Stream
import Crypto.Cipher.Types.AEAD

-- | Create a Key for a specified cipher
makeKey :: (ToSecureMem b, Cipher c) => b -> Either KeyError (Key c)
makeKey b = toKey undefined
  where sm    = toSecureMem b
        smLen = byteableLength sm
        toKey :: Cipher c => c -> Either KeyError (Key c)
        toKey cipher = case cipherKeySize cipher of
            KeySizeRange mi ma | smLen < mi -> Left KeyErrorTooSmall
                               | smLen > ma -> Left KeyErrorTooBig
                               | otherwise  -> Right $ Key sm
            KeySizeEnum l | smLen `elem` l  -> Right $ Key sm
                          | otherwise       -> Left $ KeyErrorInvalid ("valid size: " ++ show l)
            KeySizeFixed v | smLen == v     -> Right $ Key sm
                           | otherwise      -> Left $ KeyErrorInvalid ("valid size: " ++ show v)
