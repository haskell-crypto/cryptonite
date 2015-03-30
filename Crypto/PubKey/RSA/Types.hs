-- |
-- Module      : Crypto.PubKey.RSA.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.PubKey.RSA.Types
    ( Error(..)
    , Blinder(..)
    ) where

-- | Blinder which is used to obfuscate the timing
-- of the decryption primitive (used by decryption and signing).
data Blinder = Blinder !Integer !Integer
             deriving (Show,Eq)

-- | error possible during encryption, decryption or signing.
data Error =
      MessageSizeIncorrect -- ^ the message to decrypt is not of the correct size (need to be == private_size)
    | MessageTooLong       -- ^ the message to encrypt is too long
    | MessageNotRecognized -- ^ the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
    | SignatureTooLong     -- ^ the message's digest is too long
    | InvalidParameters    -- ^ some parameters lead to breaking assumptions.
    deriving (Show,Eq)

