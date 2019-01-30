-- |
-- Module      : Crypto.PubKey.RSA.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PubKey.RSA.Types
    ( Error(..)
    , Blinder(..)
    , PublicKey(..)
    , PrivateKey(..)
    , KeyPair(..)
    , toPublicKey
    , toPrivateKey
    , private_size
    , private_n
    , private_e
    ) where

import           Data.Data
import           Crypto.Internal.Imports

-- | Blinder which is used to obfuscate the timing
-- of the decryption primitive (used by decryption and signing).
data Blinder = Blinder !Integer !Integer
             deriving (Show,Eq)

-- | Error possible during encryption, decryption or signing.
data Error =
      MessageSizeIncorrect -- ^ The message to decrypt is not of the correct size (need to be == private_size)
    | MessageTooLong       -- ^ The message to encrypt is too long
    | MessageNotRecognized -- ^ The message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
    | SignatureTooLong     -- ^ The message's digest is too long
    | InvalidParameters    -- ^ Some parameters lead to breaking assumptions.
    deriving (Show,Eq)

-- | Represent a RSA public key
data PublicKey = PublicKey
    { public_size :: Int      -- ^ Size of key in bytes
    , public_n    :: Integer  -- ^ Public /p*q/
    , public_e    :: Integer  -- ^ Public exponent /e/
    } deriving (Show,Read,Eq,Data)

instance NFData PublicKey where
    rnf (PublicKey sz n e) = rnf n `seq` rnf e `seq` sz `seq` ()

-- | Represent a RSA private key.
-- 
-- Only the pub, d fields are mandatory to fill.
--
-- /p/, /q/, /dP/, /dQ/, /qinv/ are by-product during RSA generation,
-- but are useful to record here to speed up massively
-- the decrypt and sign operation.
--
-- Implementations can leave optional fields to 0.
--
data PrivateKey = PrivateKey
    { private_pub  :: PublicKey -- ^ public part of a private key (/size/, /n/, and /e/)
    , private_d    :: Integer   -- ^ private exponent /d/
    , private_p    :: Integer   -- ^ /p/ prime number
    , private_q    :: Integer   -- ^ /q/ prime number
    , private_dP   :: Integer   -- ^ /d mod (p-1)/
    , private_dQ   :: Integer   -- ^ /d mod (q-1)/
    , private_qinv :: Integer   -- ^ /q^(-1) mod p/
    } deriving (Show,Read,Eq,Data)

instance NFData PrivateKey where
    rnf (PrivateKey pub d p q dp dq qinv) =
        rnf pub `seq` rnf d `seq` rnf p `seq` rnf q `seq` rnf dp `seq` rnf dq `seq` qinv `seq` ()

-- | Get the size in bytes from a private key
private_size :: PrivateKey -> Int
private_size = public_size . private_pub

-- | Get n from a private key
private_n :: PrivateKey -> Integer
private_n = public_n . private_pub

-- | Get e from a private key
private_e :: PrivateKey -> Integer
private_e = public_e . private_pub

-- | Represent RSA KeyPair
--
-- Note the RSA private key already contains an instance of public key for efficiency.
newtype KeyPair = KeyPair PrivateKey
    deriving (Show,Read,Eq,Data,NFData)

-- | Public key of a RSA KeyPair
toPublicKey :: KeyPair -> PublicKey
toPublicKey (KeyPair priv) = private_pub priv

-- | Private key of a RSA KeyPair
toPrivateKey :: KeyPair -> PrivateKey
toPrivateKey (KeyPair priv) = priv
