-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Symmetric cipher basic types. See "AEAD Example Usage" for an example.
--

{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , BlockCipher128(..)
    , StreamCipher(..)
    , DataUnitOffset
    , KeySizeSpecifier(..)
    -- , cfb8Encrypt
    -- , cfb8Decrypt
    -- * AEAD functions
    -- $aeadExample
    , AEADMode(..)
    , CCM_M(..)
    , CCM_L(..)
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

-- $aeadExample
--
-- === __AEAD Example Usage__
--
-- @
-- {-\# LANGUAGE GeneralizedNewtypeDeriving \#-}
--
-- import Data.ByteString (ByteString)
-- import Crypto.Random (MonadRandom(..))
-- import Data.Semigroup (Semigroup)
-- import Crypto.Cipher.Types (AuthTag(..), AEADMode(..), 'aeadInit', 'aeadSimpleEncrypt', 'aeadSimpleDecrypt', 'cipherInit', 'blockSize')
-- import Crypto.Cipher.AES (AES256)
-- import Crypto.Error (CryptoFailable(..))
-- import Data.ByteArray (ByteArray, ByteArrayAccess)
-- import Data.Coerce (coerce)
--
-- -- Newtype for 256-bit AES keys
-- newtype AES256Key = AES256Key ByteString
--   deriving (Eq, Show, Ord, Semigroup, Monoid, ByteArray, ByteArrayAccess)
--
-- -- | Optional plaintext header. This data will be authenticated, but stored in plaintext. This ensures the data hasn't been changed. Useful for e.g. metadata
-- newtype PlaintextHeader = PlaintextHeader ByteString
--   deriving (Eq, Show, Ord, Semigroup, Monoid, ByteArray, ByteArrayAccess)
--
-- -- | Newtype representing data that has been encrypted
-- newtype EncryptedData a = EncryptedData ByteString
--   deriving (Eq, Show, Ord, Semigroup, Monoid, ByteArray, ByteArrayAccess)
--
-- -- | Initial vector (A random seed created for each encryption)
-- newtype IV = IV ByteString
--   deriving (Eq, Show, Ord, Semigroup, Monoid, ByteArray, ByteArrayAccess)
--
--
-- -- | Record combining the various outputs of the encryption function
-- This data can be serialized and stored in a database.
-- data EncryptedDataPackage a = EncryptedDataPackage
--   { edHeader :: PlaintextHeader
--   , edData :: EncryptedData a
--   , edIV :: IV
--   , edTag :: AuthTag
--   } deriving (Show)
--
-- -- | Create a key. This key should be stored in a secure way (not in source control)
-- -- Base64 encoding using Data.Memory.Encoding may be convenient for storing the key in ASCII
-- createKey :: MonadRandom m => m AES256Key
-- createKey = AES256Key \<$\> 'getRandomBytes' 32 -- 32 bytes * 8 = 256 bit key
--
-- -- | Note: While very fast, OCB has some patent restrictions, preventing use for military purposes
-- -- See http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm for details
-- aeadMode :: AEADMode
-- aeadMode = AEAD_OCB
--
-- encryptByteString :: MonadRandom m 
--                   => AES256Key 
--                   -> PlaintextHeader -- ^ Optional plaintext header; an empty string can be passed
--                   -> ByteString -- ^ Optional data to encrypt; an empty string can be passed (to just authenticate the header)
--                   -> m (CryptoFailable (EncryptedDataPackage a))
-- encryptByteString key header secretData = do
--   case (cipherInit key :: CryptoFailable AES256) of
--     CryptoPassed cipher -> do
--       iv <- IV \<$\> 'getRandomBytes' (blockSize cipher)
--     
--       case 'aeadInit' aeadMode cipher iv of 
--         CryptoPassed aeadContext -> do
--           let (tag, crypted) = 'aeadSimpleEncrypt' aeadContext header secretData 16 -- 16*8 = 128-bit tag length
--           return $ CryptoPassed $ EncryptedDataPackage header (EncryptedData crypted) iv tag
--         CryptoFailed ex -> return $ CryptoFailed ex
--     CryptoFailed ex -> return $ CryptoFailed ex
--
-- -- | Decrypts the output of 'encryptByteString'
-- decryptPackage :: AES256Key -> EncryptedDataPackage a -> CryptoFailable (Maybe ByteString)
-- decryptPackage key package = do
--   cipher <- cipherInit key :: CryptoFailable AES256
--   aeadContext <- 'aeadInit' aeadMode cipher (edIV package)
--   return $ coerce $ 'aeadSimpleDecrypt' aeadContext (edHeader package) (edData package) (edTag package)
--
-- @
--
-- Used from GHCi:
--
-- >>> key <- createKey
-- >>> key
-- AES256Key "f\183\GS\224\137\221\190\ETBc'\ACK\203\172\218Of\166:\140\189\159\ESCt\208\252\178\242\196\209y\230\228"
--
-- >>> crypted <- encryptByteString key (PlaintextHeader "metadata") "secret data"
-- >>> crypted
-- CryptoPassed (EncryptedDataPackage {edHeader = PlaintextHeader "metadata", edData = EncryptedData "y\143CY\137\ENQ,\139\FS\139\234", edIV = IV "A\239\177\192SE\234\143\216\165RY\149\161C\182", edTag = AuthTag {unAuthTag = ",\255\142R\210\178l\129\142]\208A\RS'-m"})
--
-- >>> let (CryptoPassed package) = crypted -- Unsafe pattern match; for GHCi only
-- >>> decryptPackage key package
-- CryptoPassed (Just "secret data")
--
-- >>> decryptPackage key (package { edHeader = PlaintextHeader "changed metadata" })
-- CryptoPassed Nothing
--
-- >>> decryptPackage key (package { edData = EncryptedData "changed data" })
-- CryptoPassed Nothing
--
-- >>> decryptPackage (AES256Key "bad key") package
-- CryptoFailed CryptoError_KeySizeInvalid