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
    , ecbEncryptLegacy
    , ecbDecryptLegacy
    , StreamCipher(..)
    , DataUnitOffset
    , KeySizeSpecifier(..)
    , AEAD(..)
    , AEADState(..)
    , AEADMode(..)
    , AEADModeImpl(..)
    -- , cfb8Encrypt
    -- , cfb8Decrypt
    -- * AEAD functions
    , module Crypto.Cipher.Types.AEAD
    -- * Initial Vector type and constructor
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block
import Crypto.Cipher.Types.Stream
import Crypto.Cipher.Types.AEAD
