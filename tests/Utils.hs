module Utils where

import Data.Char
import Data.Word
import Data.ByteString (ByteString)
import Data.Monoid (mconcat)
import qualified Data.ByteString as B

katZero :: Int
katZero = 0

--hexalise :: String -> [Word8]
hexalise s = concatMap (\c -> [ hex $ c `div` 16, hex $ c `mod` 16 ]) s
  where hex i
            | i >= 0 && i <= 9   = fromIntegral (ord '0') + i
            | i >= 10 && i <= 15 = fromIntegral (ord 'a') + i - 10
            | otherwise          = 0

splitB :: Int -> ByteString -> [ByteString]
splitB l b =
    if B.length b > l
        then
            let (b1, b2) = B.splitAt l b in
            b1 : splitB l b2
        else    
            [ b ]

