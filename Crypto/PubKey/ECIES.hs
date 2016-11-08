-- |
-- Module      : Crypto.PubKey.ECIES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- IES with Elliptic curve <https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme>
--
module Crypto.PubKey.ECIES (
      Curve(..)
    , EllipticCurve(..)
    , Curve_P256R1(..)
    , Curve_P384R1(..)
    , Curve_P521R1(..)
    , KeyPair(..)
    , CurveKeyPair(..)
    , SharedSecret(..)
    , deriveEncrypt
    , deriveDecrypt
    , curveBytes
    ) where

import Crypto.ECC
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.Random.Types

deriveEncrypt :: MonadRandom randomly => Curve -> randomly CurveKeyPair
deriveEncrypt = generateKeyPair

--- | Generating a shared key using our private key and
---   the public key of the other party.
deriveDecrypt :: (Integer, Integer) -- ^ The public key of the sender
              -> CurveKeyPair       -- ^ The private key of the receiver
              -> SharedSecret
deriveDecrypt (x,y) (CurveKeyPair kp) = shared
  where
    s = keypairPrivate kp
    curve = curveOfScalar s
    p = curveIntegersToPoint curve x y
    (x', _) = curvePointToIntegers $ curvePointSmul s p
    len = curveBytes $ curveOfScalar s
    shared = SharedSecret $ i2ospOf_ len x'
