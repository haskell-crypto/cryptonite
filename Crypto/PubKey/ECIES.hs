-- |
-- Module      : Crypto.PubKey.ECIES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- IES with Elliptic curve <https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme>
--
module Crypto.PubKey.ECIES
    ( deriveEncrypt
    , deriveDecrypt
    ) where

import           Crypto.ECC
import           Crypto.Random

-- | Generate random a new Shared secret and the associated point
-- to do a ECIES style encryption
deriveEncrypt :: (MonadRandom randomly, EllipticCurveDH curve)
              => Point curve -- ^ the public key of the receiver
              -> randomly (Point curve, SharedSecret)
deriveEncrypt pub = do
    (KeyPair rPoint rScalar) <- curveGenerateKeyPair
    return (rPoint, ecdh rScalar pub)

-- | Derive the shared secret with the receiver key
-- and the R point of the scheme.
deriveDecrypt :: EllipticCurveDH curve
              => Point curve  -- ^ The received R (supposedly, randomly generate on the encrypt side)
              -> Scalar curve -- ^ The secret key of the receiver
              -> SharedSecret
deriveDecrypt point secret = ecdh secret point
