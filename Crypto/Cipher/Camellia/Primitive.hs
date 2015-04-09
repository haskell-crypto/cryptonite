
-- |
-- Module      : Crypto.Cipher.Camellia.Primitive
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- this only cover Camellia 128 bits for now, API will change once
-- 192 and 256 mode are implemented too

module Crypto.Cipher.Camellia.Primitive
    ( Camellia
    , initCamellia
    , encrypt
    , decrypt
    ) where

import Data.Word
import Data.Vector.Unboxed
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B

import Crypto.Error
import Crypto.Internal.ByteArray
import Crypto.Internal.Words

data Mode = Decrypt | Encrypt

w128tow64 :: Word128 -> (Word64, Word64)
w128tow64 (Word128 w1 w2) = (w1, w2)

w64tow128 :: (Word64, Word64) -> Word128
w64tow128 (x1, x2) = Word128 x1 x2

w64tow8 :: Word64 -> (Word8, Word8, Word8, Word8, Word8, Word8, Word8, Word8)
w64tow8 x = (t1, t2, t3, t4, t5, t6, t7, t8)
    where
        t1 = fromIntegral (x `shiftR` 56)
        t2 = fromIntegral (x `shiftR` 48)
        t3 = fromIntegral (x `shiftR` 40)
        t4 = fromIntegral (x `shiftR` 32)
        t5 = fromIntegral (x `shiftR` 24)
        t6 = fromIntegral (x `shiftR` 16)
        t7 = fromIntegral (x `shiftR` 8)
        t8 = fromIntegral (x)

w8tow64 :: B.ByteString -> Word64
w8tow64 b = (sh t1 56 .|. sh t2 48 .|. sh t3 40 .|. sh t4 32 .|. sh t5 24 .|. sh t6 16 .|. sh t7 8 .|. sh t8 0)
    where
        t1     = B.unsafeIndex b 0
        t2     = B.unsafeIndex b 1
        t3     = B.unsafeIndex b 2
        t4     = B.unsafeIndex b 3
        t5     = B.unsafeIndex b 4
        t6     = B.unsafeIndex b 5
        t7     = B.unsafeIndex b 6
        t8     = B.unsafeIndex b 7
        sh i r = (fromIntegral i) `shiftL` r

w64tow32 :: Word64 -> (Word32, Word32)
w64tow32 w = (fromIntegral (w `shiftR` 32), fromIntegral (w .&. 0xffffffff))

w32tow64 :: (Word32, Word32) -> Word64
w32tow64 (x1, x2) = ((fromIntegral x1) `shiftL` 32) .|. (fromIntegral x2)

sbox :: Vector Word8
sbox = fromList
    [112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65
    , 35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189
    ,134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26
    ,166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77
    ,139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153
    ,223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215
    , 20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34
    ,254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80
    ,170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210
    , 16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148
    ,135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226
    , 82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46
    ,233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89
    ,120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250
    ,114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164
    , 64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158
    ]

sbox1 :: Word8 -> Word8
sbox1 x = sbox ! (fromIntegral x)

sbox2 :: Word8 -> Word8
sbox2 x = sbox1 x `rotateL` 1;

sbox3 :: Word8 -> Word8
sbox3 x = sbox1 x `rotateL` 7;

sbox4 :: Word8 -> Word8
sbox4 x = sbox1 (x `rotateL` 1);

sigma1, sigma2, sigma3, sigma4, sigma5, sigma6 :: Word64
sigma1 = 0xA09E667F3BCC908B
sigma2 = 0xB67AE8584CAA73B2
sigma3 = 0xC6EF372FE94F82BE
sigma4 = 0x54FF53A5F1D36F1C
sigma5 = 0x10E527FADE682D1D
sigma6 = 0xB05688C2B3E6C1FD

rotl128 :: Word128 -> Int -> Word128
rotl128 v               0  = v
rotl128 (Word128 x1 x2) 64 = Word128 x2 x1

rotl128 v@(Word128 x1 x2) w
    | w > 64    = (v `rotl128` 64) `rotl128` (w - 64)
    | otherwise = Word128 (x1high .|. x2low) (x2high .|. x1low)
        where
            splitBits i = (i .&. complement x, i .&. x)
                where x = 2 ^ w - 1
            (x1high, x1low) = splitBits (x1 `rotateL` w)
            (x2high, x2low) = splitBits (x2 `rotateL` w)

data Camellia = Camellia
    { k  :: Vector Word64
    , kw :: Vector Word64
    , ke :: Vector Word64
    }

setKeyInterim :: ByteArray key => key -> (Word128, Word128, Word128, Word128)
setKeyInterim keyseed = (w64tow128 kL, w64tow128 kR, w64tow128 kA, w64tow128 kB)
  where kL = (byteArrayToW64BE keyseed 0, byteArrayToW64BE keyseed 8)
        kR = (0, 0)

        kA = let d1 = (fst kL `xor` fst kR)
                 d2 = (snd kL `xor` snd kR)
                 d3 = d2 `xor` feistel d1 sigma1
                 d4 = d1 `xor` feistel d3 sigma2
                 d5 = d4 `xor` (fst kL)
                 d6 = d3 `xor` (snd kL)
                 d7 = d6 `xor` feistel d5 sigma3
                 d8 = d5 `xor` feistel d7 sigma4
              in (d8, d7)

        kB = let d1 = (fst kA `xor` fst kR)
                 d2 = (snd kA `xor` snd kR)
                 d3 = d2 `xor` feistel d1 sigma5
                 d4 = d1 `xor` feistel d3 sigma6
              in (d4, d3)

-- | Initialize a 128-bit key
-- Return the initialized key or a error message if the given 
-- keyseed was not 16-bytes in length.
--
initCamellia :: ByteArray key
             => key -- ^ The key to create the camellia context
             -> CryptoFailable Camellia
initCamellia key
    | byteArrayLength key /= 16 = CryptoFailed $ CryptoError_KeySizeInvalid
    | otherwise                 =
        let (kL, _, kA, _) = setKeyInterim key in

        let (kw1, kw2) = w128tow64 (kL `rotl128` 0) in
        let (k1, k2)   = w128tow64 (kA `rotl128` 0) in
        let (k3, k4)   = w128tow64 (kL `rotl128` 15) in
        let (k5, k6)   = w128tow64 (kA `rotl128` 15) in
        let (ke1, ke2) = w128tow64 (kA `rotl128` 30) in --ke1 = (KA <<<  30) >> 64; ke2 = (KA <<<  30) & MASK64;
        let (k7, k8)   = w128tow64 (kL `rotl128` 45) in --k7  = (KL <<<  45) >> 64; k8  = (KL <<<  45) & MASK64;
        let (k9, _)    = w128tow64 (kA `rotl128` 45) in --k9  = (KA <<<  45) >> 64;
        let (_, k10)   = w128tow64 (kL `rotl128` 60) in
        let (k11, k12) = w128tow64 (kA `rotl128` 60) in
        let (ke3, ke4) = w128tow64 (kL `rotl128` 77) in
        let (k13, k14) = w128tow64 (kL `rotl128` 94) in
        let (k15, k16) = w128tow64 (kA `rotl128` 94) in
        let (k17, k18) = w128tow64 (kL `rotl128` 111) in
        let (kw3, kw4) = w128tow64 (kA `rotl128` 111) in

        CryptoPassed $ Camellia
            { kw = fromList [ kw1, kw2, kw3, kw4 ]
            , ke = fromList [ ke1, ke2, ke3, ke4 ]
            , k  = fromList [ k1, k2, k3, k4, k5, k6, k7, k8, k9,
                      k10, k11, k12, k13, k14, k15, k16, k17, k18 ]
            }

feistel :: Word64 -> Word64 -> Word64
feistel fin sk = 
    let x = fin `xor` sk in
    let (t1, t2, t3, t4, t5, t6, t7, t8) = w64tow8 x in
    let t1' = sbox1 t1 in
    let t2' = sbox2 t2 in
    let t3' = sbox3 t3 in
    let t4' = sbox4 t4 in
    let t5' = sbox2 t5 in
    let t6' = sbox3 t6 in
    let t7' = sbox4 t7 in
    let t8' = sbox1 t8 in
    let y1 = t1' `xor` t3' `xor` t4' `xor` t6' `xor` t7' `xor` t8' in
    let y2 = t1' `xor` t2' `xor` t4' `xor` t5' `xor` t7' `xor` t8' in
    let y3 = t1' `xor` t2' `xor` t3' `xor` t5' `xor` t6' `xor` t8' in
    let y4 = t2' `xor` t3' `xor` t4' `xor` t5' `xor` t6' `xor` t7' in
    let y5 = t1' `xor` t2' `xor` t6' `xor` t7' `xor` t8' in
    let y6 = t2' `xor` t3' `xor` t5' `xor` t7' `xor` t8' in
    let y7 = t3' `xor` t4' `xor` t5' `xor` t6' `xor` t8' in
    let y8 = t1' `xor` t4' `xor` t5' `xor` t6' `xor` t7' in
    w8tow64 $ B.pack [y1, y2, y3, y4, y5, y6, y7, y8]

fl :: Word64 -> Word64 -> Word64
fl fin sk =
    let (x1, x2) = w64tow32 fin in
    let (k1, k2) = w64tow32 sk in
    let y2 = x2 `xor` ((x1 .&. k1) `rotateL` 1) in
    let y1 = x1 `xor` (y2 .|. k2) in
    w32tow64 (y1, y2)

flinv :: Word64 -> Word64 -> Word64
flinv fin sk =
    let (y1, y2) = w64tow32 fin in
    let (k1, k2) = w64tow32 sk in
    let x1 = y1 `xor` (y2 .|. k2) in
    let x2 = y2 `xor` ((x1 .&. k1) `rotateL` 1) in
    w32tow64 (x1, x2)

{- in decrypt mode 0->17 1->16 ... -}
getKeyK :: Mode -> Camellia -> Int -> Word64
getKeyK Encrypt key i = k key ! i
getKeyK Decrypt key i = k key ! (17 - i)

{- in decrypt mode 0->3 1->2 2->1 3->0 -}
getKeyKe :: Mode -> Camellia -> Int -> Word64
getKeyKe Encrypt key i = ke key ! i
getKeyKe Decrypt key i = ke key ! (3 - i)

{- in decrypt mode 0->2 1->3 2->0 3->1 -}
getKeyKw :: Mode -> Camellia -> Int -> Word64
getKeyKw Encrypt key i = kw key ! i
getKeyKw Decrypt key i = kw key ! ((i + 2) `mod` 4)

{- perform the following
    D2 = D2 ^ F(D1, k1);     // Round 1
    D1 = D1 ^ F(D2, k2);     // Round 2
    D2 = D2 ^ F(D1, k3);     // Round 3
    D1 = D1 ^ F(D2, k4);     // Round 4
    D2 = D2 ^ F(D1, k5);     // Round 5
    D1 = D1 ^ F(D2, k6);     // Round 6
 -}
doBlockRound :: Mode -> Camellia -> Word64 -> Word64 -> Int -> (Word64, Word64)
doBlockRound mode key d1 d2 i =
    let r1 = d2 `xor` feistel d1 (getKeyK mode key (0+i)) in     {- Round 1+i -}
    let r2 = d1 `xor` feistel r1 (getKeyK mode key (1+i)) in     {- Round 2+i -}
    let r3 = r1 `xor` feistel r2 (getKeyK mode key (2+i)) in     {- Round 3+i -}
    let r4 = r2 `xor` feistel r3 (getKeyK mode key (3+i)) in     {- Round 4+i -}
    let r5 = r3 `xor` feistel r4 (getKeyK mode key (4+i)) in     {- Round 5+i -}
    let r6 = r4 `xor` feistel r5 (getKeyK mode key (5+i)) in     {- Round 6+i -}
    (r6, r5)

doBlock :: Mode -> Camellia -> Word128 -> Word128
doBlock mode key m =
    let (d1, d2) = w128tow64 m in

    let d1a = d1 `xor` (getKeyKw mode key 0) in {- Prewhitening -}
    let d2a = d2 `xor` (getKeyKw mode key 1) in

    let (d1b, d2b) = doBlockRound mode key d1a d2a 0 in

    let d1c = fl    d1b (getKeyKe mode key 0) in {- FL -}
    let d2c = flinv d2b (getKeyKe mode key 1) in {- FLINV -}

    let (d1d, d2d) = doBlockRound mode key d1c d2c 6 in

    let d1e = fl    d1d (getKeyKe mode key 2) in {- FL -}
    let d2e = flinv d2d (getKeyKe mode key 3) in {- FLINV -}

    let (d1f, d2f) = doBlockRound mode key d1e d2e 12 in

    let d2g = d2f `xor` (getKeyKw mode key 2) in {- Postwhitening -}
    let d1g = d1f `xor` (getKeyKw mode key 3) in
    w64tow128 (d2g, d1g)

{- encryption for 128 bits blocks -}
encryptBlock :: Camellia -> Word128 -> Word128
encryptBlock = doBlock Encrypt

{- decryption for 128 bits blocks -}
decryptBlock :: Camellia -> Word128 -> Word128
decryptBlock = doBlock Decrypt

-- | Encrypts the given ByteString using the given Key
encrypt :: ByteArray ba
        => Camellia     -- ^ The key to use
        -> ba           -- ^ The data to encrypt
        -> ba
encrypt key = byteArrayMapAsWord128 (encryptBlock key)

-- | Decrypts the given ByteString using the given Key
decrypt :: ByteArray ba
        => Camellia     -- ^ The key to use
        -> ba           -- ^ The data to decrypt
        -> ba
decrypt key = byteArrayMapAsWord128 (decryptBlock key)
