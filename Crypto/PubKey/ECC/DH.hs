-- |
-- Module      : Crypto.PubKey.ECC.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Elliptic curve Diffie Hellman
--
module Crypto.PubKey.ECC.DH
    (
      Scalar
    , Point
    , KeyPair(..)
    , SharedSecret(..)
    , generateKeyPair
    , getShared
    ) where

import Crypto.ECC
import Crypto.Random.Types

-- | Generating a pair of private key (scalar d) and public key (point Q).
generateKeyPair :: (MonadRandom m, EllipticCurveDH curve)
                => m (KeyPair curve)
generateKeyPair = curveGenerateKeyPair

--- | Generating a shared key using our private key and
---   the public key of the other party.
getShared :: EllipticCurveDH curve
          => Scalar curve -- ^ The private key of the receiver
          -> Point curve  -- ^ The public key of the sender
          -> SharedSecret
getShared = ecdh
