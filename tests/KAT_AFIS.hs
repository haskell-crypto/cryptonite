{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
module KAT_AFIS (tests) where

import Control.Applicative
import Control.Monad

import Crypto.Hash
import Crypto.Random
import qualified Crypto.Data.AFIS as AFIS

import Data.ByteString.Char8 ()
import qualified Data.ByteString as B

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit

mergeVec =
    [ (3
      , hash :: HashFunctionBS SHA1
      , "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\xd4\x76\xc8\x58\xbd\xf0\x15\xbe\x9f\x40\xe3\x65\x20\x1c\x9c\xb8\xd8\x1c\x16\x64"
      )
    , (3
      , hash :: HashFunctionBS SHA1
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\xd6\x75\xc8\x59\xbb\xf7\x11\xbb\x95\x4b\xeb\x6c\x2e\x13\x90\xb5\xca\x0f\x06\x75\x17\x70\x39\x28"
      )
    ]

mergeKATs = map toProp $ zip mergeVec [(0 :: Int)..]
  where toProp ((nbExpands, hashF, expected, dat), i) =
            testCase ("merge " ++ show i) (expected @=? AFIS.merge hashF nbExpands dat)

data AFISParams = forall a . HashAlgorithm a => AFISParams B.ByteString Int (HashFunctionBS a) ChaChaDRG

instance Show AFISParams where
    show (AFISParams dat expand _ _) = "data: " ++ show dat ++ " expanded: " ++ show expand

instance Arbitrary AFISParams where
    arbitrary = AFISParams <$> arbitraryBS <*> choose (2,2) <*> elements [hash :: HashFunctionBS SHA1] <*> arbitrary
      where arbitraryBS = choose (3,46) >>= \sz -> B.pack <$> replicateM sz arbitrary 

instance Arbitrary ChaChaDRG where
    arbitrary = drgNewTest <$> arbitrary

tests = testGroup "AFIS"
    [ testGroup "KAT merge" mergeKATs
    , testProperty "merge.split == id" $ \(AFISParams bs e hf rng) -> bs == (AFIS.merge hf e $ fst (AFIS.split hf rng e bs))
    ]
