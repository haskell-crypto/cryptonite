-- |
-- Module      : Crypto.Cipher.Blowfish.Primitive
-- License     : BSD-style
-- Stability   : experimental
-- Portability : Good

-- Crypto.Cipher.Blowfish.Primitive, copyright (c) 2012 Stijn van Drongelen
-- based on: BlowfishAux.hs (C) 2002 HardCore SoftWare, Doug Hoyte
--           (as found in Crypto-4.2.4)

module Crypto.Cipher.Blowfish.Primitive
    ( Context
    , initBlowfish
    , encrypt
    , decrypt
    ) where

import Data.Vector (Vector, (!), (//))
import qualified Data.Vector as V
import Data.Bits
import Data.Word
import qualified Data.ByteString as B

import Crypto.Error
import Crypto.Internal.ByteArray
import Crypto.Cipher.Blowfish.Box

-- | variable keyed blowfish state
data Context = BF Pbox Sbox Sbox Sbox Sbox

encrypt, decrypt :: Context -> B.ByteString -> B.ByteString
encrypt = cipher . selectEncrypt
decrypt = cipher . selectDecrypt

selectEncrypt, selectDecrypt :: Context -> (Pbox, Context)
selectEncrypt x@(BF p _ _ _ _) = (p, x)
selectDecrypt x@(BF p _ _ _ _) = (V.reverse p, x)

cipher :: (Pbox, Context) -> B.ByteString -> B.ByteString
cipher (p, bs) b
    | B.length b == 0 = B.empty
    | B.length b `mod` 8 /= 0 = error "invalid data length"
    | otherwise = B.concat $ doChunks 8 (fromW32Pair . coreCrypto p bs . toW32Pair) b

initBlowfish :: ByteArray key => key -> CryptoFailable Context
initBlowfish key
    | len > (448 `div` 8) = CryptoFailed $ CryptoError_KeySizeInvalid
    | len == 0            = keyFromByteString (B.replicate (18*4) 0)
    | otherwise           = keyFromByteString . B.pack . take (18*4) . cycle . B.unpack . byteArrayToBS $ key 
  where len = byteArrayLength key

keyFromByteString :: B.ByteString -> CryptoFailable Context
keyFromByteString k
    | B.length k /= (18 * 4) = CryptoFailed CryptoError_KeySizeInvalid
    | otherwise              = CryptoPassed . bfMakeKey . (\ws -> V.generate 18 (ws!!)) . w8tow32 . B.unpack $ k
  where
    w8tow32 :: [Word8] -> [Word32]
    w8tow32 [] = []
    w8tow32 (a:b:c:d:xs) = ( (fromIntegral a `shiftL` 24) .|.
                             (fromIntegral b `shiftL` 16) .|.
                             (fromIntegral c `shiftL`  8) .|.
                             (fromIntegral d) ) : w8tow32 xs
    w8tow32 _ = error $ "internal error: Crypto.Cipher.Blowfish:keyFromByteString"

coreCrypto :: Pbox -> Context -> (Word32, Word32) -> (Word32, Word32)
coreCrypto p bs i = (\(l,r) -> (r `xor` p!17, l `xor` p!16))
                  $ V.foldl' (doRound bs) i (V.take 16 p)
  where
    doRound :: Context -> (Word32, Word32) -> Word32 -> (Word32, Word32)
    doRound (BF _ s0 s1 s2 s3) (l,r) pv =
        let newr = l `xor` pv
            newl = r `xor` (f newr)
        in (newl, newr)
          where
            f   :: Word32 -> Word32
            f t = let a = s0 ! (fromIntegral $ (t `shiftR` 24) .&. 0xff)
                      b = s1 ! (fromIntegral $ (t `shiftR` 16) .&. 0xff)
                      c = s2 ! (fromIntegral $ (t `shiftR` 8) .&. 0xff)
                      d = s3 ! (fromIntegral $ t .&. 0xff)
                  in ((a + b) `xor` c) + d

bfMakeKey :: Vector Word32 -> Context
bfMakeKey k = procKey (0,0) (BF (V.zipWith xor k iPbox) iSbox0 iSbox1 iSbox2 iSbox3) 0

procKey :: (Word32, Word32) -> Context -> Int -> Context
procKey _     tpbf                    1042 = tpbf
procKey (l,r) tpbf@(BF p s0 s1 s2 s3)    i = procKey (nl,nr) (newbf i) (i+2)
  where (nl,nr) = coreCrypto p tpbf (l,r)
        newbf x | x <   18 = (BF (p//[(x,nl),(x+1,nr)]) s0 s1 s2 s3)
                | x <  274 = (BF p (s0//[(x-18,nl),(x-17,nr)]) s1 s2 s3)
                | x <  530 = (BF p s0 (s1//[(x-274,nl),(x-273,nr)]) s2 s3)
                | x <  786 = (BF p s0 s1 (s2//[(x-530,nl),(x-529,nr)]) s3)
                | x < 1042 = (BF p s0 s1 s2 (s3//[(x-786,nl),(x-785,nr)]))
                | otherwise = error "internal error: Crypto.Cipher.Blowfish:procKey "


doChunks :: Int -> (B.ByteString -> B.ByteString) -> B.ByteString -> [B.ByteString]
doChunks n f b =
    let (x, rest) = B.splitAt n b in
    if B.length rest >= n
        then f x : doChunks n f rest
        else [ f x ]

toW32Pair :: B.ByteString -> (Word32, Word32)
toW32Pair b = let (x1, x2) = B.splitAt 4 b
                  w1 = decode32be x1
                  w2 = decode32be x2
              in (w1,w2)

fromW32Pair :: (Word32, Word32) -> B.ByteString
fromW32Pair (w1,w2)
    = let w1' = fromIntegral w1
          w2' = fromIntegral w2
          w = (w1' `shiftL` 32) .|. w2'
      in encode64be w

decode32be :: B.ByteString -> Word32
decode32be s = id $!
    (fromIntegral (s `B.index` 0) `shiftL` 24) .|.
    (fromIntegral (s `B.index` 1) `shiftL` 16) .|.
    (fromIntegral (s `B.index` 2) `shiftL`  8) .|.
    (fromIntegral (s `B.index` 3) )

encode64be :: Word64 -> B.ByteString
encode64be w = B.pack . map fromIntegral $
                [ (w `shiftR` 56) .&. 0xff
                , (w `shiftR` 48) .&. 0xff
                , (w `shiftR` 40) .&. 0xff
                , (w `shiftR` 32) .&. 0xff
                , (w `shiftR` 24) .&. 0xff
                , (w `shiftR` 16) .&. 0xff
                , (w `shiftR` 8) .&. 0xff
                , w .&. 0xff
                ]

