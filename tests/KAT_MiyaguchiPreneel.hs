
module KAT_MiyaguchiPreneel (tests) where

import           Crypto.Cipher.AES (AES128)
import           Crypto.ConstructHash.MiyaguchiPreneel

import           Imports

import           Data.Char (digitToInt)
import qualified Data.ByteString as BS
import qualified Data.ByteArray as B


runMP128 :: ByteString -> ByteString
runMP128 s = B.convert (mp s :: MiyaguchiPreneel AES128)

hxs :: String -> ByteString
hxs = BS.pack . rec' where
    dtoW8 = fromIntegral . digitToInt
    rec' (' ':xs)  =  rec' xs
    rec' (x:y:xs)  =  dtoW8 x * 16 + dtoW8 y : rec' xs
    rec' [_]       =  error "hxs: invalid hex pattern."
    rec' []        =  []

gAES128 :: TestTree
gAES128 =
  igroup "aes128"
  [ runMP128  BS.empty
    @?=       hxs "66e94bd4 ef8a2c3b 884cfa59 ca342b2e"
  , runMP128 (hxs "01000000 00000000 00000000 00000000")
    @?=       hxs "46711816 e91d6ff0 59bbbf2b f58e0fd3"
  , runMP128 (hxs "00000000 00000000 00000000 00000001")
    @?=       hxs "58e2fcce fa7e3061 367f1d57 a4e7455b"
  , runMP128     (hxs $
                  "00000000 00000000 00000000 00000000" ++
                  "01")
    @?=       hxs "a5ff35ae 097adf5d 646abf5e bf4c16f4"
  ]

igroup :: TestName -> [Assertion] -> TestTree
igroup nm = testGroup nm . zipWith (flip ($)) [1..] . map icase
  where
    icase c i = testCase (show (i :: Int)) c

vectors :: TestTree
vectors =
  testGroup "KATs"
  [ gAES128 ]

tests :: TestTree
tests =
    testGroup "MiyaguchiPreneel"
    [ vectors ]
