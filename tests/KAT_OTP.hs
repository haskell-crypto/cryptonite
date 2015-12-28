{-# LANGUAGE OverloadedStrings #-}


module KAT_OTP
    ( tests
    )
where

import Crypto.Hash.Algorithms (SHA1(..))
import Crypto.OTP
import Data.ByteString (ByteString)
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

totpExpected :: [(Word64, Word32)]
totpExpected =
    [ (59        , 94287082)
    , (1111111109, 07081804)
    , (1111111111, 14050471)
    , (1234567890, 89005924)
    , (2000000000, 69279037)
    , (20000000000, 65353130)
    ]

otpKey = "12345678901234567890" :: ByteString

makeHOTPKATs = concatMap makeTest (zip3 is counts hotps)
  where
    is :: [Int]
    is = [1..]

    counts = map fst hotpExpected
    hotps  = map snd hotpExpected

    makeTest (i, count, password) =
        [ testCase (show i) (assertEqual "" password (hotp OTP6 otpKey count))
        ]

makeTOTPKATs = concatMap makeTest (zip3 is times otps)
  where
    is :: [Int]
    is = [1..]

    times = map fst totpExpected
    otps  = map snd totpExpected
    Right params = mkTOTPParams SHA1 0 30 OTP8

    makeTest (i, now, password) =
        [ testCase (show i) (assertEqual "" password (totp params otpKey (fromIntegral now)))
        ]

-- resynching with the expected value should just return the current counter + 1
prop_resyncExpected ctr window = resynchronize OTP6 window key ctr (otp, []) == Just (ctr + 1)
  where
    key = "1234" :: ByteString
    otp = hotp OTP6 key ctr


tests = testGroup "OTP"
    [ testGroup "HOTP"
        [ testGroup "KATs" makeHOTPKATs
        , testGroup "properties"
            [ testProperty "resync-expected" prop_resyncExpected
            ]
        ]
    , testGroup "TOTP"
        [ testGroup "KATs" makeTOTPKATs
        ]
    ]
