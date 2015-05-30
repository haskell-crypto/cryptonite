{-# LANGUAGE OverloadedStrings #-}
module KAT_PubKey.P256 (tests) where

import           Control.Arrow (second)

import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.P256 as P256

import           Test.Tasty.KAT
import           Test.Tasty.KAT.FileLoader
import           Data.ByteArray (Bytes)
import           Crypto.Number.Serialize (i2ospOf)
import           Crypto.Error

import           Imports

tests = testGroup "P256"
    [ testGroup "scalar"
        [ testProperty "marshalling" $ \(Positive r') ->
            let r = r' `mod` curveN
                rBytes = i2ospScalar r
             in case P256.scalarFromBinary rBytes of
                    CryptoFailed err    -> error (show err)
                    CryptoPassed scalar -> rBytes `propertyEq` P256.scalarToBinary scalar
        ]
    ]
  where
    curve  = ECC.getCurveByName ECC.SEC_p256r1
    curveN = ECC.ecc_n . ECC.common_curve $ curve

    i2ospScalar :: Integer -> Bytes
    i2ospScalar i =
        case i2ospOf 32 i of
            Nothing -> error "invalid size of P256 scalar"
            Just b  -> b
