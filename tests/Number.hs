module Number (tests) where

import Imports

import Crypto.Number.Basic
import Data.Bits

tests = testGroup "number"
    [ testProperty "num-bits" $ \(Positive i) ->
        and [ (numBits (2^i-1) == i)
            , (numBits (2^i) == i+1)
            , (numBits (2^i + (2^i-1)) == i+1)
            ]
    , testProperty "num-bits2" $ \(Positive i) ->
        not (i `testBit` numBits i) && (i `testBit` (numBits i - 1))
    ]
