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
import Crypto.Internal.Words
import Crypto.Cipher.Blowfish.Box

-- | variable keyed blowfish state
data Context = BF Pbox Sbox Sbox Sbox Sbox

encrypt, decrypt :: ByteArray ba => Context -> ba -> ba
encrypt = cipher . selectEncrypt
decrypt = cipher . selectDecrypt

selectEncrypt, selectDecrypt :: Context -> (Pbox, Context)
selectEncrypt x@(BF p _ _ _ _) = (p, x)
selectDecrypt x@(BF p _ _ _ _) = (V.reverse p, x)

cipher :: ByteArray ba => (Pbox, Context) -> ba -> ba
cipher (p, bs) b
    | byteArrayLength b == 0         = empty
    | byteArrayLength b `mod` 8 /= 0 = error "invalid data length"
    | otherwise                      = byteArrayMapAsWord64 (coreCrypto p bs) b

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

coreCrypto :: Pbox -> Context -> Word64 -> Word64
coreCrypto p bs input = (\x -> let (l,r) = w64to32 x in w32to64 (r `xor` p!17, l `xor` p!16))
                  $ V.foldl' (doRound bs) input (V.take 16 p)
  where
    doRound :: Context -> Word64 -> Word32 -> Word64
    doRound (BF _ s0 s1 s2 s3) i pv =
        let (l,r) = w64to32 i in
        let newr = l `xor` pv
            newl = r `xor` (f newr)
        in w32to64 (newl, newr)
          where
            f   :: Word32 -> Word32
            f t = let a = s0 ! (fromIntegral $ (t `shiftR` 24) .&. 0xff)
                      b = s1 ! (fromIntegral $ (t `shiftR` 16) .&. 0xff)
                      c = s2 ! (fromIntegral $ (t `shiftR` 8) .&. 0xff)
                      d = s3 ! (fromIntegral $ t .&. 0xff)
                  in ((a + b) `xor` c) + d

bfMakeKey :: Vector Word32 -> Context
bfMakeKey k = procKey 0 (BF (V.zipWith xor k iPbox) iSbox0 iSbox1 iSbox2 iSbox3) 0

procKey :: Word64 -> Context -> Int -> Context
procKey _     tpbf                    1042 = tpbf
procKey input tpbf@(BF p s0 s1 s2 s3)    i = procKey ni (newbf i) (i+2)
  where ni      = coreCrypto p tpbf input
        (nl,nr) = w64to32 ni
        newbf x | x <   18 = (BF (p//[(x,nl),(x+1,nr)]) s0 s1 s2 s3)
                | x <  274 = (BF p (s0//[(x-18,nl),(x-17,nr)]) s1 s2 s3)
                | x <  530 = (BF p s0 (s1//[(x-274,nl),(x-273,nr)]) s2 s3)
                | x <  786 = (BF p s0 s1 (s2//[(x-530,nl),(x-529,nr)]) s3)
                | x < 1042 = (BF p s0 s1 s2 (s3//[(x-786,nl),(x-785,nr)]))
                | otherwise = error "internal error: Crypto.Cipher.Blowfish:procKey "

