module Utils where

import Control.Monad (replicateM)
import Data.Char
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Test.Tasty.QuickCheck

newtype ChunkingLen = ChunkingLen [Int]
    deriving (Show,Eq)

instance Arbitrary ChunkingLen where
    arbitrary = ChunkingLen `fmap` replicateM 16 (choose (0,14))

chunkS :: ChunkingLen -> ByteString -> [ByteString]
chunkS (ChunkingLen originalChunks) = loop originalChunks
  where loop l bs
            | B.null bs = []
            | otherwise =
                case l of
                    (x:xs) -> let (b1, b2) = B.splitAt x bs in b1 : loop xs b2
                    []     -> loop originalChunks bs

chunksL :: ChunkingLen -> L.ByteString -> L.ByteString
chunksL (ChunkingLen originalChunks) = L.fromChunks . loop originalChunks . L.toChunks
  where loop _ []       = []
        loop l (b:bs)
            | B.null b  = loop l bs
            | otherwise =
                case l of
                    (x:xs) -> let (b1, b2) = B.splitAt x b in b1 : loop xs (b2:bs)
                    []     -> loop originalChunks (b:bs)

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

