{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module KAT_Blake2 (tests) where

import           Crypto.Hash (digestFromByteString)
import           Crypto.Hash.Algorithms
import qualified Crypto.MAC.KeyedBlake2 as KB

import qualified Data.ByteString as B

import Imports


data MACVector hash = MACVector
    { macMessage :: ByteString
    , macKey    :: ByteString
    , macResult :: KB.KeyedBlake2 hash
    }

instance Show (KB.KeyedBlake2 hash) where
    show (KB.KeyedBlake2 d) = show d

digest :: KB.HashBlake2 hash => ByteString -> KB.KeyedBlake2 hash
digest = maybe (error "cannot get digest") KB.KeyedBlake2 . digestFromByteString


-- From: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/
vectorsBlake2bKAT :: [MACVector (Blake2b 512)]
vectorsBlake2bKAT =
    [ MACVector
        { macMessage = ""
        , macKey     = fixedKey
        , macResult  = digest "\x10\xeb\xb6\x77\x00\xb1\x86\x8e\xfb\x44\x17\x98\x7a\xcf\x46\x90\xae\x9d\x97\x2f\xb7\xa5\x90\xc2\xf0\x28\x71\x79\x9a\xaa\x47\x86\xb5\xe9\x96\xe8\xf0\xf4\xeb\x98\x1f\xc2\x14\xb0\x05\xf4\x2d\x2f\xf4\x23\x34\x99\x39\x16\x53\xdf\x7a\xef\xcb\xc1\x3f\xc5\x15\x68"
        }
    , MACVector
        { macMessage = "\x00"
        , macKey     = fixedKey
        , macResult  = digest "\x96\x1f\x6d\xd1\xe4\xdd\x30\xf6\x39\x01\x69\x0c\x51\x2e\x78\xe4\xb4\x5e\x47\x42\xed\x19\x7c\x3c\x5e\x45\xc5\x49\xfd\x25\xf2\xe4\x18\x7b\x0b\xc9\xfe\x30\x49\x2b\x16\xb0\xd0\xbc\x4e\xf9\xb0\xf3\x4c\x70\x03\xfa\xc0\x9a\x5e\xf1\x53\x2e\x69\x43\x02\x34\xce\xbd"
        }
    , MACVector
        { macMessage = B.pack [ 0x00 .. 0xfe ]
        , macKey     = fixedKey
        , macResult  = digest "\x14\x27\x09\xd6\x2e\x28\xfc\xcc\xd0\xaf\x97\xfa\xd0\xf8\x46\x5b\x97\x1e\x82\x20\x1d\xc5\x10\x70\xfa\xa0\x37\x2a\xa4\x3e\x92\x48\x4b\xe1\xc1\xe7\x3b\xa1\x09\x06\xd5\xd1\x85\x3d\xb6\xa4\x10\x6e\x0a\x7b\xf9\x80\x0d\x37\x3d\x6d\xee\x2d\x46\xd6\x2e\xf2\xa4\x61"
        }
    ]
    where fixedKey = B.pack [ 0x00 .. 0x3f ]

vectorsBlake2bpKAT :: [MACVector (Blake2bp 512)]
vectorsBlake2bpKAT =
    [ MACVector
        { macMessage = ""
        , macKey     = fixedKey
        , macResult  = digest "\x9d\x94\x61\x07\x3e\x4e\xb6\x40\xa2\x55\x35\x7b\x83\x9f\x39\x4b\x83\x8c\x6f\xf5\x7c\x9b\x68\x6a\x3f\x76\x10\x7c\x10\x66\x72\x8f\x3c\x99\x56\xbd\x78\x5c\xbc\x3b\xf7\x9d\xc2\xab\x57\x8c\x5a\x0c\x06\x3b\x9d\x9c\x40\x58\x48\xde\x1d\xbe\x82\x1c\xd0\x5c\x94\x0a"
        }
    , MACVector
        { macMessage = "\x00"
        , macKey     = fixedKey
        , macResult  = digest "\xff\x8e\x90\xa3\x7b\x94\x62\x39\x32\xc5\x9f\x75\x59\xf2\x60\x35\x02\x9c\x37\x67\x32\xcb\x14\xd4\x16\x02\x00\x1c\xbb\x73\xad\xb7\x92\x93\xa2\xdb\xda\x5f\x60\x70\x30\x25\x14\x4d\x15\x8e\x27\x35\x52\x95\x96\x25\x1c\x73\xc0\x34\x5c\xa6\xfc\xcb\x1f\xb1\xe9\x7e"
        }
    , MACVector
        { macMessage = B.pack [ 0x00 .. 0xfe ]
        , macKey     = fixedKey
        , macResult  = digest "\x96\xfb\xcb\xb6\x0b\xd3\x13\xb8\x84\x50\x33\xe5\xbc\x05\x8a\x38\x02\x74\x38\x57\x2d\x7e\x79\x57\xf3\x68\x4f\x62\x68\xaa\xdd\x3a\xd0\x8d\x21\x76\x7e\xd6\x87\x86\x85\x33\x1b\xa9\x85\x71\x48\x7e\x12\x47\x0a\xad\x66\x93\x26\x71\x6e\x46\x66\x7f\x69\xf8\xd7\xe8"
        }
    ]
    where fixedKey = B.pack [ 0x00 .. 0x3f ]

vectorsBlake2sKAT :: [MACVector (Blake2s 256)]
vectorsBlake2sKAT =
    [ MACVector
        { macMessage = ""
        , macKey     = fixedKey
        , macResult  = digest "\x48\xa8\x99\x7d\xa4\x07\x87\x6b\x3d\x79\xc0\xd9\x23\x25\xad\x3b\x89\xcb\xb7\x54\xd8\x6a\xb7\x1a\xee\x04\x7a\xd3\x45\xfd\x2c\x49"
        }
    , MACVector
        { macMessage = "\x00"
        , macKey     = fixedKey
        , macResult  = digest "\x40\xd1\x5f\xee\x7c\x32\x88\x30\x16\x6a\xc3\xf9\x18\x65\x0f\x80\x7e\x7e\x01\xe1\x77\x25\x8c\xdc\x0a\x39\xb1\x1f\x59\x80\x66\xf1"
        }
    , MACVector
        { macMessage = B.pack [ 0x00 .. 0xfe ]
        , macKey     = fixedKey
        , macResult  = digest "\x3f\xb7\x35\x06\x1a\xbc\x51\x9d\xfe\x97\x9e\x54\xc1\xee\x5b\xfa\xd0\xa9\xd8\x58\xb3\x31\x5b\xad\x34\xbd\xe9\x99\xef\xd7\x24\xdd"
        }
    ]
    where fixedKey = B.pack [ 0x00 .. 0x1f ]

vectorsBlake2spKAT :: [MACVector (Blake2sp 256)]
vectorsBlake2spKAT =
    [ MACVector
        { macMessage = ""
        , macKey     = fixedKey
        , macResult  = digest "\x71\x5c\xb1\x38\x95\xae\xb6\x78\xf6\x12\x41\x60\xbf\xf2\x14\x65\xb3\x0f\x4f\x68\x74\x19\x3f\xc8\x51\xb4\x62\x10\x43\xf0\x9c\xc6"
        }
    , MACVector
        { macMessage = "\x00"
        , macKey     = fixedKey
        , macResult  = digest "\x40\x57\x8f\xfa\x52\xbf\x51\xae\x18\x66\xf4\x28\x4d\x3a\x15\x7f\xc1\xbc\xd3\x6a\xc1\x3c\xbd\xcb\x03\x77\xe4\xd0\xcd\x0b\x66\x03"
        }
    , MACVector
        { macMessage = B.pack [ 0x00 .. 0xfe ]
        , macKey     = fixedKey
        , macResult  = digest "\x0c\x8a\x36\x59\x7d\x74\x61\xc6\x3a\x94\x73\x28\x21\xc9\x41\x85\x6c\x66\x83\x76\x60\x6c\x86\xa5\x2d\xe0\xee\x41\x04\xc6\x15\xdb"
        }
    ]
    where fixedKey = B.pack [ 0x00 .. 0x1f ]

macTests :: [TestTree]
macTests =
    [ testGroup "Blake2b_512" (concatMap toMACTest $ zip is vectorsBlake2bKAT)
    , testGroup "Blake2bp_512" (concatMap toMACTest $ zip is vectorsBlake2bpKAT)
    , testGroup "Blake2s_512" (concatMap toMACTest $ zip is vectorsBlake2sKAT)
    , testGroup "Blake2sp_512" (concatMap toMACTest $ zip is vectorsBlake2spKAT)
    ]
    where toMACTest (i, MACVector{..}) =
            [ testCase (show i) (macResult @=? KB.keyedBlake2 macKey macMessage)
            , testCase ("incr-" ++ show i) (macResult @=?
                        KB.finalize (KB.update (KB.initialize macKey) macMessage))
            ]
          is :: [Int]
          is = [1..]

data MacIncremental a = MacIncremental ByteString ByteString (KB.KeyedBlake2 a)
    deriving (Show,Eq)

instance KB.HashBlake2 a => Arbitrary (MacIncremental a) where
    arbitrary = do
        key <- arbitraryBSof 32 64
        msg <- arbitraryBSof 1 99
        return $ MacIncremental key msg (KB.keyedBlake2 key msg)

data MacIncrementalList a = MacIncrementalList ByteString [ByteString] (KB.KeyedBlake2 a)
    deriving (Show,Eq)

instance KB.HashBlake2 a => Arbitrary (MacIncrementalList a) where
    arbitrary = do
        key <- arbitraryBSof 32 64
        msgs <- choose (1,20) >>= \n -> replicateM n (arbitraryBSof 1 99)
        return $ MacIncrementalList key msgs (KB.keyedBlake2 key (B.concat msgs))

macIncrementalTests :: [TestTree]
macIncrementalTests =
    [ testIncrProperties "Blake2b_512" (Blake2b :: Blake2b 512)
    , testIncrProperties "Blake2bp_512" (Blake2bp :: Blake2bp 512)
    , testIncrProperties "Blake2s_256" (Blake2s :: Blake2s 256)
    , testIncrProperties "Blake2sp_256" (Blake2sp :: Blake2sp 256)
    ]
  where
        testIncrProperties :: KB.HashBlake2 a => TestName -> a -> TestTree
        testIncrProperties name a = testGroup name
            [ testProperty "list-one" (prop_inc0 a)
            , testProperty "list-multi" (prop_inc1 a)
            ]

        prop_inc0 :: KB.HashBlake2 a => a -> MacIncremental a -> Bool
        prop_inc0 _ (MacIncremental secret msg result) =
            result `assertEq` KB.finalize (KB.update (KB.initialize secret) msg)

        prop_inc1 :: KB.HashBlake2 a => a -> MacIncrementalList a -> Bool
        prop_inc1 _ (MacIncrementalList secret msgs result) =
            result `assertEq` KB.finalize (foldl' KB.update (KB.initialize secret) msgs)

tests = testGroup "Blake2"
    [ testGroup "KATs" macTests
    , testGroup "properties" macIncrementalTests ]
