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
      Curve(..)
    , EllipticCurve(..)
    , Curve_P256R1(..)
    , Curve_P521R1(..)
    , CurveKeyPair(..)
    , SharedSecret(..)
    , generateKeyPair
    , setPublicKey
    , getShared
    ) where

import Crypto.ECC
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.Random.Types

--- | Generating a shared key using our private key and
---   the public key of the other party.
getShared :: CurveKeyPair -- ^ The private key of the receiver and
                          --   the public key of the sender
          -> SharedSecret
getShared (CurveKeyPair kp) = shared
  where
    s = keypairPrivate kp
    p = keypairPublic kp
    (x, _) = curvePointToIntegers $ curvePointSmul s p
    nbBits = curveNbBits (curveOfScalar s)
    shared = SharedSecret $ i2ospOf_ ((nbBits + 7) `div` 8) x
