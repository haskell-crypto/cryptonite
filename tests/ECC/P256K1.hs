{-# LANGUAGE OverloadedStrings #-}
module ECC.P256K1 ( tests ) where

import Imports
import Data.Maybe (fromJust)
import qualified Data.ByteString as B
import Crypto.PubKey.ECC.ECDSA (PrivateKey(..), Signature, signDigestWith) -- sign
import Crypto.ECC (Curve_P256K1(..))
import Crypto.PubKey.ECC.Types (getCurveByName, CurveName(SEC_p256k1))
import Crypto.Number.Serialize (os2ip)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.PubKey.ECC.P256K1 (parseDer, rfc6979)
import Crypto.Random.ChaChaDRG (initialize)
--import Crypto.Random.Types (withDRG)

import Crypto.Secp256k1 (signRecMsg, secKey, msg, importSig, convertRecSig)
import Crypto.Hash (hashWith)
import Data.ByteArray (convert)

--drg = initialize (B.replicate 40 (fromIntegral 1))

curve = getCurveByName SEC_p256k1

signmsg = "aaa" :: ByteString
digest = hashWith SHA256 signmsg
signmsg2 = fromJust $ msg $ convert $ digest
signkey = "\xf6\x52\x55\x09\x4d\x77\x73\xed\x8d\xd4\x17\xba\xdc\x9f\xc0\x45\xc1\xf8\x0f\xdc\x5b\x2d\x25\x17\x2b\x03\x1c\xe6\x93\x3e\x03\x9a" :: ByteString
signkey1 = PrivateKey curve $ os2ip signkey
signkey2 = fromJust $ secKey signkey
signder = "\x30\x45\x02\x21\x00\xbe\xa7\xe8\x0a\x36\x0f\xce\x4c\x9b\x75\x72\
          \\xfa\x9d\x2d\x8d\xae\x02\xcf\x12\x81\x66\xa9\x35\xf6\xa1\x92\x0b\
          \\xbc\x7b\x46\xb2\x77\x02\x20\x7e\x8d\xaf\xe2\xaa\xfe\x4d\xd0\xcb\
          \\xed\xbe\x45\x00\x8e\x62\x32\xa5\xcc\xef\x8a\x97\xa2\xe0\xa7\x92\
          \\x32\xfe\xfa\xb1\x7f\x3c\x6c" :: ByteString
signder1 :: Signature
signder1 = fromJust $ parseDer signder
signder2 = fromJust $ importSig signder

tests = testGroup "ECC.P256K1"
    [ testGroup "vectors"
        [ testCase "sign-native"  $ signder2 @=? (convertRecSig $ signRecMsg signkey2 signmsg2)
        --, testCase "sign-thislib" $ signder1 @=? fst (withDRG drg $ sign signkey1 SHA256 signmsg)
        , testCase "sign-thislib" $ signder1 @=? (fromJust $ signDigestWith (rfc6979 digest signkey1 0) signkey1 digest)
        ]
    ]
