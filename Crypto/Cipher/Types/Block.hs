-- |
-- Module      : Crypto.Cipher.Types.Block
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- block cipher basic types
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Types.Block
    (
    -- * BlockCipher
      BlockCipher(..)
    , ecbEncryptLegacy
    , ecbDecryptLegacy
    -- * initialization vector (IV)
    , IV(..)
    , makeIV
    , nullIV
    , ivAdd
    -- * XTS
    , XTS
    -- * AEAD
    , AEAD(..)
    , AEADState(..)
    , AEADModeImpl(..)
    -- * CFB 8 bits
    --, cfb8Encrypt
    --, cfb8Decrypt
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B (unsafeCreate)
import Data.Byteable
import Data.Word
import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.GF
import Crypto.Cipher.Types.Utils

import Crypto.Internal.ByteArray

import Foreign.Ptr
import Foreign.Storable

-- | an IV parametrized by the cipher
data IV c = forall byteArray . ByteArray byteArray => IV byteArray

instance BlockCipher c => ByteArrayAccess (IV c) where
    withByteArray (IV z) f = withByteArray z f
    byteArrayLength (IV z) = byteArrayLength z

type XTS cipher = (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ByteString       -- ^ Data
               -> ByteString       -- ^ Processed Data

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int

    -- | Encrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbEncrypt :: ByteArray ba => cipher -> ba -> ba

    -- | Decrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbDecrypt :: ByteArray ba => cipher -> ba -> ba

    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cbcEncrypt = cbcEncryptGeneric
    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cbcDecrypt = cbcDecryptGeneric

    -- | encrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbEncrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cfbEncrypt = cfbEncryptGeneric
    -- | decrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbDecrypt :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    cfbDecrypt = cfbDecryptGeneric

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombine :: ByteArray ba => cipher -> IV cipher -> ba -> ba
    ctrCombine = ctrCombineGeneric

    -- | Initialize a new AEAD State
    --
    -- When Nothing is returns, it means the mode is not handled.
    aeadInit :: Byteable iv => AEADMode -> cipher -> iv -> Maybe (AEAD cipher)
    aeadInit _ _ _ = Nothing

ecbEncryptLegacy :: ByteArray ba
                 => (cipher -> ByteString -> ByteString)
                 -> cipher -> ba -> ba
ecbEncryptLegacy f cipher input =
    byteArrayFromBS $ f cipher (byteArrayToBS input)

ecbDecryptLegacy :: ByteArray ba
                 => (cipher -> ByteString -> ByteString)
                 -> cipher -> ba -> ba
ecbDecryptLegacy f cipher input =
    byteArrayFromBS $ f cipher (byteArrayToBS input)

-- | class of block cipher with a 128 bits block size
class BlockCipher cipher => BlockCipher128 cipher where
    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsEncrypt :: (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ByteString       -- ^ Plaintext
               -> ByteString       -- ^ Ciphertext
    xtsEncrypt = undefined -- xtsEncryptGeneric

    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize, and the cipher
    -- need to process 128 bits block only
    xtsDecrypt :: (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ByteString       -- ^ Ciphertext
               -> ByteString       -- ^ Plaintext
    xtsDecrypt = undefined -- xtsDecryptGeneric

-- | Authenticated Encryption with Associated Data algorithms
data AEAD cipher = AEAD cipher (AEADState cipher)

-- | Wrapper for any AEADState
data AEADState cipher = forall st . AEADModeImpl cipher st => AEADState st

-- | Class of AEAD Mode implementation
class BlockCipher cipher => AEADModeImpl cipher state where
    aeadStateAppendHeader :: cipher -> state -> ByteString -> state
    aeadStateEncrypt      :: cipher -> state -> ByteString -> (ByteString, state)
    aeadStateDecrypt      :: cipher -> state -> ByteString -> (ByteString, state)
    aeadStateFinalize     :: cipher -> state -> Int -> AuthTag

-- | Create an IV for a specified block cipher
makeIV :: (Byteable b, BlockCipher c) => b -> Maybe (IV c)
makeIV b = toIV undefined
  where toIV :: BlockCipher c => c -> Maybe (IV c)
        toIV cipher
          | byteableLength b == sz = Just (IV $ toBytes b)
          | otherwise              = Nothing
          where sz = blockSize cipher

-- | Create an IV that is effectively representing the number 0
nullIV :: BlockCipher c => IV c
nullIV = toIV undefined
  where toIV :: BlockCipher c => c -> IV c
        toIV cipher = IV $ B.replicate (blockSize cipher) 0

-- | Increment an IV by a number.
--
-- Assume the IV is in Big Endian format.
ivAdd :: BlockCipher c => IV c -> Int -> IV c
ivAdd (IV b) i = IV $ copy b
  where copy :: ByteArray bs => bs -> bs
        copy bs = byteArrayCopyAndFreeze bs $ \p -> do
            let until0 accu = do
                  r <- loop accu (byteArrayLength bs - 1) p
                  case r of
                      0 -> return ()
                      _ -> until0 r
            until0 i

        loop :: Int -> Int -> Ptr Word8 -> IO Int
        loop 0   _   _ = return 0
        loop acc ofs p = do
            v <- peek (p `plusPtr` ofs) :: IO Word8
            let accv    = acc + fromIntegral v
                (hi,lo) = accv `divMod` 256
            poke (p `plusPtr` ofs) (fromIntegral lo :: Word8)
            if ofs == 0
                then return hi
                else loop hi (ofs - 1) p

cbcEncryptGeneric :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cbcEncryptGeneric cipher ivini input = byteArrayConcat $ doEnc ivini $ chunk (blockSize cipher) input
  where doEnc _  []     = []
        doEnc iv (i:is) =
            let o = ecbEncrypt cipher $ byteArrayXor iv i
             in o : doEnc (IV o) is

cbcDecryptGeneric :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cbcDecryptGeneric cipher ivini input = byteArrayConcat $ doDec ivini $ chunk (blockSize cipher) input
  where
        doDec _  []     = []
        doDec iv (i:is) =
            let o = byteArrayXor iv $ ecbDecrypt cipher i
             in o : doDec (IV i) is

cfbEncryptGeneric :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cfbEncryptGeneric cipher ivini input = byteArrayConcat $ doEnc ivini $ chunk (blockSize cipher) input
  where
        doEnc _  []     = []
        doEnc (IV iv) (i:is) =
            let o = byteArrayXor i $ ecbEncrypt cipher iv
             in o : doEnc (IV o) is

cfbDecryptGeneric :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
cfbDecryptGeneric cipher ivini input = byteArrayConcat $ doDec ivini $ chunk (blockSize cipher) input
  where
        doDec _  []     = []
        doDec (IV iv) (i:is) =
            let o = byteArrayXor i $ ecbEncrypt cipher iv
             in o : doDec (IV i) is

ctrCombineGeneric :: (ByteArray ba, BlockCipher cipher) => cipher -> IV cipher -> ba -> ba
ctrCombineGeneric cipher ivini input = byteArrayConcat $ doCnt ivini $ chunk (blockSize cipher) input
  where doCnt _  [] = []
        doCnt iv@(IV ivd) (i:is) =
            let ivEnc = ecbEncrypt cipher ivd
             in byteArrayXor i ivEnc : doCnt (ivAdd iv 1) is

{-
xtsEncryptGeneric :: BlockCipher128 cipher => XTS cipher
xtsEncryptGeneric = xtsGeneric ecbEncrypt

xtsDecryptGeneric :: BlockCipher128 cipher => XTS cipher
xtsDecryptGeneric = xtsGeneric ecbDecrypt

xtsGeneric :: BlockCipher128 cipher
           => (cipher -> B.ByteString -> B.ByteString)
           -> (cipher, cipher)
           -> IV cipher
           -> DataUnitOffset
           -> ByteString
           -> ByteString
xtsGeneric f (cipher, tweakCipher) iv sPoint input
    | blockSize cipher /= 16 = error "XTS mode is only available with cipher that have a block size of 128 bits"
    | otherwise = byteArrayConcat $ doXts iniTweak $ chunk (blockSize cipher) input
  where encTweak = ecbEncrypt tweakCipher iv
        iniTweak = iterate xtsGFMul encTweak !! fromIntegral sPoint
        doXts _     []     = []
        doXts tweak (i:is) =
            let o = bxor (f cipher $ bxor i tweak) tweak
             in o : doXts (xtsGFMul tweak) is
-}

{-
-- | Encrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Encrypt :: BlockCipher a => a -> IV a -> B.ByteString -> B.ByteString
cfb8Encrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbEncrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` out)

-- | Decrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Decrypt :: BlockCipher a => a -> IV a -> B.ByteString -> B.ByteString
cfb8Decrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbDecrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` B.head m')
-}
