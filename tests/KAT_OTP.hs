{-# LANGUAGE OverloadedStrings #-}


module KAT_OTP
    ( tests
    )
where

import Crypto.OTP
import Imports

-- | Test values from Appendix D of http://tools.ietf.org/html/rfc4226
hotpExpected :: [(Word64, Word32)]
hotpExpected =
    [ (0, 755224)
    , (1, 287082)
    , (3, 969429)
    , (4, 338314)
    , (5, 254676)
    , (6, 287922)
    , (7, 162583)
    , (8, 399871)
    , (9, 520489)
    ]

makeKATs = concatMap makeTest (zip3 is counts hotps)
  where
    is :: [Int]
    is = [1..]
    hotpKey = "12345678901234567890" :: ByteString

    counts = map fst hotpExpected
    hotps  = map snd hotpExpected

    makeTest (i, count, password) =
        [ testCase (show i) (assertEqual "" password (hotp OTP6 hotpKey count))
        ]

tests = testGroup "OTP"
    [ testGroup "KATs" makeKATs
    ]
