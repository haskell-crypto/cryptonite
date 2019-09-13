{-# LANGUAGE OverloadedStrings #-}
module ECC.P256K1 ( tests ) where

import Imports
import Data.Maybe (fromJust, isNothing)
import qualified Data.ByteString as B
import Crypto.PubKey.ECC.ECDSA (PrivateKey(..), Signature, signDigestWith, ensureLowS)
import Crypto.PubKey.ECC.Types (getCurveByName, CurveName(SEC_p256k1))
import Crypto.Number.Serialize (os2ip)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.PubKey.ECC.P256K1 (parseDer, rfc6979, Scalar, pointDh, Point, pointFromBinary, scalarFromInteger)
import Crypto.Error (maybeCryptoError)
import Crypto.Hash (hashWith)

curve = getCurveByName SEC_p256k1

signmsg = "aaa" :: ByteString
digest = hashWith SHA256 signmsg
signkey = "\xf6\x52\x55\x09\x4d\x77\x73\xed\x8d\xd4\x17\xba\xdc\x9f\xc0\x45\xc1\xf8\x0f\xdc\x5b\x2d\x25\x17\x2b\x03\x1c\xe6\x93\x3e\x03\x9a" :: ByteString
signkey1 = PrivateKey curve $ os2ip signkey
signder = "\x30\x45\x02\x21\x00\xbe\xa7\xe8\x0a\x36\x0f\xce\x4c\x9b\x75\x72\
          \\xfa\x9d\x2d\x8d\xae\x02\xcf\x12\x81\x66\xa9\x35\xf6\xa1\x92\x0b\
          \\xbc\x7b\x46\xb2\x77\x02\x20\x7e\x8d\xaf\xe2\xaa\xfe\x4d\xd0\xcb\
          \\xed\xbe\x45\x00\x8e\x62\x32\xa5\xcc\xef\x8a\x97\xa2\xe0\xa7\x92\
          \\x32\xfe\xfa\xb1\x7f\x3c\x6c" :: ByteString
signder1 :: Signature
signder1 = fromJust $ maybeCryptoError $ parseDer signder

pri :: Scalar
pri = fromJust $ maybeCryptoError $ scalarFromInteger $ os2ip $ B.replicate 32 0x12
pub :: Point
pub = fromJust $ maybeCryptoError $ pointFromBinary ("\x02\x8d\x75\x00\xdd\x4c\x12\x68\x5d\x1f\x56\x8b\x4c\x2b\x50\x48\xe8\x53\x4b\x87\x33\x19\xf3\xa8\xda\xa6\x12\xb4\x69\x13\x2e\xc7\xf7" :: ByteString)
ref :: ByteString
ref = "\x1e\x2f\xb3\xc8\xfe\x8f\xb9\xf2\x62\xf6\x49\xf6\x4d\x26\xec\xf0\xf2\xc0\xa8\x05\xa7\x67\xcf\x02\xdc\x2d\x77\xa6\xef\x1f\xdc\xc3"

tests = testGroup "ECC.P256K1"
    [ testCase "sign-thislib" $ signder1 @=? (ensureLowS curve $ fromJust $ signDigestWith (rfc6979 digest signkey1 0) signkey1 digest)
    , testCase "ecdh" $ ref @=? pointDh pri pub
    , testCase "scalarFromInteger 0" $ True  @=? (isNothing $ maybeCryptoError $ scalarFromInteger 0)
    , testCase "scalarFromInteger 1" $ False @=? (isNothing $ maybeCryptoError $ scalarFromInteger 1)
    ]
