-- |
-- Module      : Crypto.Cipher.Types.Base
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- symmetric cipher basic types
--
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Cipher.Types.Base
    ( KeySizeSpecifier(..)
    , Cipher(..)
    , AuthTag(..)
    , AEADMode(..)
    , DataUnitOffset
    ) where

import Data.Word
import Data.ByteString (ByteString)

import Crypto.Internal.ByteArray
import Crypto.Error

-- | Different specifier for key size in bytes
data KeySizeSpecifier =
      KeySizeRange Int Int -- ^ in the range [min,max]
    | KeySizeEnum  [Int]   -- ^ one of the specified values
    | KeySizeFixed Int     -- ^ a specific size
    deriving (Show,Eq)

-- | Offset inside an XTS data unit, measured in block size.
type DataUnitOffset = Word32

-- | Authentification Tag for AE cipher mode
newtype AuthTag = AuthTag { unAuthTag :: ByteString }
    deriving (Show, ByteArrayAccess)

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = byteArrayConstEq a b

-- | AEAD Mode
data AEADMode =
      AEAD_OCB -- OCB3
    | AEAD_CCM
    | AEAD_EAX
    | AEAD_CWC
    | AEAD_GCM
    deriving (Show,Eq)

-- | Symmetric cipher class.
class Cipher cipher where
    -- | Initialize a cipher context from a key
    cipherInit    :: ByteArray key => key -> CryptoFailable cipher
    -- | Cipher name
    cipherName    :: cipher -> String
    -- | return the size of the key required for this cipher.
    -- Some cipher accept any size for key
    cipherKeySize :: cipher -> KeySizeSpecifier
