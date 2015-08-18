{-# LANGUAGE OverloadedStrings #-}
module Padding (tests) where

import qualified Data.ByteString as B
import Imports
import Crypto.Error

import Crypto.Data.Padding

cases =
    [ ("abcdef", 8, "abcdef\x02\x02")
    , ("abcd", 4, "abcd\x04\x04\x04\x04")
    , ("xyze", 5, "xyze\x01")
    ]

--instance Arbitrary where

testPad :: Int -> (B.ByteString, Int, B.ByteString) -> TestTree
testPad n (inp, sz, padded) =
    testCase (show n) $ propertyHoldCase [ eqTest "padded" padded (pad (PKCS7 sz) inp)
                                         , eqTest "unpadded" (Just inp) (unpad (PKCS7 sz) padded)
                                         ]

tests = testGroup "Padding"
    [ testGroup "Cases" $ map (uncurry testPad) (zip [1..] cases)
    ]
