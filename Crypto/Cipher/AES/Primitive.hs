{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Module      : Crypto.Cipher.AES.Primitive
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Cipher.AES.Primitive
    (
    -- * block cipher data types
      AES

    -- * Authenticated encryption block cipher types
    , AESGCM
    , AESOCB

    -- * creation
    , initAES

    -- * misc
    , genCTR
    , genCounter

    -- * encryption
    , encryptECB
    , encryptCBC
    , encryptCTR
    , encryptXTS
    , encryptGCM
    , encryptOCB

    -- * decryption
    , decryptECB
    , decryptCBC
    , decryptCTR
    , decryptXTS
    , decryptGCM
    , decryptOCB
    ) where

import Data.Word
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.C.String
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B (ByteString(PS), mallocByteString, memcpy)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Error
import Crypto.Cipher.Types
import Crypto.Internal.ByteArray
import Crypto.Internal.Memory
import Crypto.Cipher.Types.Block (IV(..))

import Data.SecureMem

instance Cipher AES where
    cipherName    _ = "AES"
    cipherKeySize _ = KeySizeEnum [16,24,32]
    cipherInit k    = initAES k

instance BlockCipher AES where
    blockSize _ = 16
    ecbEncrypt = encryptECB
    ecbDecrypt = decryptECB
    cbcEncrypt = encryptCBC
    cbcDecrypt = decryptCBC
    ctrCombine = encryptCTR
    {-
    aeadInit AEAD_GCM aes iv = Just $ AEAD aes $ AEADState $ gcmInit aes iv
    aeadInit AEAD_OCB aes iv = Just $ AEAD aes $ AEADState $ ocbInit aes iv
    aeadInit _        _    _ = Nothing
    -}
instance BlockCipher128 AES where 
    xtsEncrypt = encryptXTS
    xtsDecrypt = decryptXTS

-- | AES Context (pre-processed key)
newtype AES = AES SecureBytes

-- | AESGCM State
newtype AESGCM = AESGCM SecureBytes

-- | AESOCB State
newtype AESOCB = AESOCB SecureBytes

sizeGCM :: Int
sizeGCM = 80

sizeOCB :: Int
sizeOCB = 160

keyToPtr :: AES -> (Ptr AES -> IO a) -> IO a
keyToPtr (AES b) f = withByteArray b (f . castPtr)

ivToPtr :: ByteArrayAccess iv => iv -> (Ptr Word8 -> IO a) -> IO a
ivToPtr iv f = withByteArray iv (f . castPtr)

{-
ivCopyPtr :: IV AES -> (Ptr Word8 -> IO ()) -> IO (IV AES)
ivCopyPtr (IV iv) f = do
    newIV <- byteArrayAlloc 16 $ \newPtr -> do
                withByteArray iv $ \ivPtr -> B.memcpy newPtr ivPtr 16
    withByteArray newIV $ f
    return $! IV newIV
-}

withKeyAndIV :: ByteArrayAccess iv => AES -> iv -> (Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKeyAndIV ctx iv f = keyToPtr ctx $ \kptr -> ivToPtr iv $ \ivp -> f kptr ivp

withKey2AndIV :: ByteArrayAccess iv => AES -> AES -> iv -> (Ptr AES -> Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKey2AndIV key1 key2 iv f =
    keyToPtr key1 $ \kptr1 -> keyToPtr key2 $ \kptr2 -> ivToPtr iv $ \ivp -> f kptr1 kptr2 ivp

withGCMKeyAndCopySt :: AES -> AESGCM -> (Ptr AESGCM -> Ptr AES -> IO a) -> IO (a, AESGCM)
withGCMKeyAndCopySt aes (AESGCM gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- secureMemCopy gcmSt
        a     <- withSecureMemPtr newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESGCM newSt)

withNewGCMSt :: AESGCM -> (Ptr AESGCM -> IO ()) -> IO AESGCM
withNewGCMSt (AESGCM gcmSt) f = withSecureMemCopy gcmSt (f . castPtr) >>= \sm2 -> return (AESGCM sm2)

withOCBKeyAndCopySt :: AES -> AESOCB -> (Ptr AESOCB -> Ptr AES -> IO a) -> IO (a, AESOCB)
withOCBKeyAndCopySt aes (AESOCB gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- secureMemCopy gcmSt
        a     <- withSecureMemPtr newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESOCB newSt)

-- | Initialize a new context with a key
--
-- Key need to be of length 16, 24 or 32 bytes. any other values will cause undefined behavior
initAES :: ByteArrayAccess key => key -> CryptoFailable AES
initAES k
    | len == 16 = CryptoPassed $ initWithRounds 10
    | len == 24 = CryptoPassed $ initWithRounds 12
    | len == 32 = CryptoPassed $ initWithRounds 14
    | otherwise = CryptoFailed CryptoError_KeySizeInvalid
  where len = byteArrayLength k
        initWithRounds nbR = AES $ unsafeCreateSecureMem (16+2*2*16*nbR) aesInit
        aesInit ptr = withByteArray k $ \ikey ->
            c_aes_init (castPtr ptr) (castPtr ikey) (fromIntegral len)

-- | encrypt using Electronic Code Book (ECB)
{-# NOINLINE encryptECB #-}
encryptECB :: ByteArray ba => AES -> ba -> ba
encryptECB = doECB c_aes_encrypt_ecb

-- | encrypt using Cipher Block Chaining (CBC)
{-# NOINLINE encryptCBC #-}
encryptCBC :: ByteArray ba
           => AES        -- ^ AES Context
           -> IV AES     -- ^ Initial vector of AES block size
           -> ba         -- ^ plaintext
           -> ba         -- ^ ciphertext
encryptCBC = doCBC c_aes_encrypt_cbc

-- | generate a counter mode pad. this is generally xor-ed to an input
-- to make the standard counter mode block operations.
--
-- if the length requested is not a multiple of the block cipher size,
-- more data will be returned, so that the returned bytestring is
-- a multiple of the block cipher size.
{-# NOINLINE genCTR #-}
genCTR :: ByteArray ba
       => AES    -- ^ Cipher Key.
       -> IV AES -- ^ usually a 128 bit integer.
       -> Int    -- ^ length of bytes required.
       -> ba
genCTR ctx (IV iv) len
    | len <= 0  = empty
    | otherwise = byteArrayAllocAndFreeze (nbBlocks * 16) generate
  where generate o = withKeyAndIV ctx iv $ \k i -> c_aes_gen_ctr (castPtr o) k i (fromIntegral nbBlocks)
        (nbBlocks',r) = len `quotRem` 16
        nbBlocks = if r == 0 then nbBlocks' else nbBlocks' + 1

-- | generate a counter mode pad. this is generally xor-ed to an input
-- to make the standard counter mode block operations.
--
-- if the length requested is not a multiple of the block cipher size,
-- more data will be returned, so that the returned bytestring is
-- a multiple of the block cipher size.
--
-- Similiar to 'genCTR' but also return the next IV for continuation
{-# NOINLINE genCounter #-}
genCounter :: AES
           -> IV AES
           -> Int
           -> (ByteString, IV AES)
genCounter ctx iv len
    | len <= 0  = (B.empty, iv)
    | otherwise = unsafePerformIO $ do
        undefined
        {-
        fptr  <- B.mallocByteString outputLength
        newIv <- withForeignPtr fptr $ \o ->
                    keyToPtr ctx $ \k ->
                    ivCopyPtr iv $ \i -> do
                        c_aes_gen_ctr_cont (castPtr o) k i (fromIntegral nbBlocks)
        let !out = B.PS fptr 0 outputLength
        return $! (out `seq` newIv `seq` (out, newIv))
  where
        (nbBlocks',r) = len `quotRem` 16
        nbBlocks = if r == 0 then nbBlocks' else nbBlocks' + 1
        outputLength = nbBlocks * 16
        -}

{- TODO: when genCTR has same AESIV requirements for IV, add the following rules:
 - RULES "snd . genCounter" forall ctx iv len .  snd (genCounter ctx iv len) = genCTR ctx iv len
 -}

-- | encrypt using Counter mode (CTR)
--
-- in CTR mode encryption and decryption is the same operation.
{-# NOINLINE encryptCTR #-}
encryptCTR :: ByteArray ba
           => AES        -- ^ AES Context
           -> IV AES     -- ^ initial vector of AES block size (usually representing a 128 bit integer)
           -> ba         -- ^ plaintext input
           -> ba         -- ^ ciphertext output
encryptCTR ctx iv input
    | len <= 0                 = empty
    | byteArrayLength iv /= 16 = error $ "AES error: IV length must be block size (16). Its length is: " ++ (show $ byteArrayLength iv)
    | otherwise = byteArrayAllocAndFreeze len doEncrypt
  where doEncrypt o = withKeyAndIV ctx iv $ \k v -> withByteArray input $ \i ->
                      c_aes_encrypt_ctr (castPtr o) k v i (fromIntegral len)
        len = byteArrayLength input

-- | encrypt using Galois counter mode (GCM)
-- return the encrypted bytestring and the tag associated
--
-- note: encrypted data is identical to CTR mode in GCM, however
-- a tag is also computed.
{-# NOINLINE encryptGCM #-}
encryptGCM :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArray ba)
           => AES        -- ^ AES Context
           -> iv         -- ^ IV initial vector of any size
           -> aad        -- ^ data to authenticate (AAD)
           -> ba         -- ^ data to encrypt
           -> (ba, AuthTag) -- ^ ciphertext and tag
encryptGCM = doGCM gcmAppendEncrypt

-- | encrypt using OCB v3
-- return the encrypted bytestring and the tag associated
{-# NOINLINE encryptOCB #-}
encryptOCB :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArray ba)
           => AES        -- ^ AES Context
           -> iv         -- ^ IV initial vector of any size
           -> aad        -- ^ data to authenticate (AAD)
           -> ba         -- ^ data to encrypt
           -> (ba, AuthTag) -- ^ ciphertext and tag
encryptOCB = doOCB ocbAppendEncrypt

-- | encrypt using XTS
--
-- the first key is the normal block encryption key
-- the second key is used for the initial block tweak
{-# NOINLINE encryptXTS #-}
encryptXTS :: ByteArray ba
           => (AES,AES)  -- ^ AES cipher and tweak context
           -> IV AES     -- ^ a 128 bits IV, typically a sector or a block offset in XTS
           -> Word32     -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
           -> ba         -- ^ input to encrypt
           -> ba         -- ^ output encrypted
encryptXTS = doXTS c_aes_encrypt_xts

-- | decrypt using Electronic Code Book (ECB)
{-# NOINLINE decryptECB #-}
decryptECB :: ByteArray ba => AES -> ba -> ba
decryptECB = doECB c_aes_decrypt_ecb

-- | decrypt using Cipher block chaining (CBC)
{-# NOINLINE decryptCBC #-}
decryptCBC :: ByteArray ba => AES -> IV AES -> ba -> ba
decryptCBC = doCBC c_aes_decrypt_cbc

-- | decrypt using Counter mode (CTR).
--
-- in CTR mode encryption and decryption is the same operation.
decryptCTR :: ByteArray ba
           => AES        -- ^ AES Context
           -> IV AES     -- ^ initial vector, usually representing a 128 bit integer
           -> ba         -- ^ ciphertext input
           -> ba         -- ^ plaintext output
decryptCTR = encryptCTR

-- | decrypt using XTS
{-# NOINLINE decryptXTS #-}
decryptXTS :: ByteArray ba
           => (AES,AES)  -- ^ AES cipher and tweak context
           -> IV AES     -- ^ a 128 bits IV, typically a sector or a block offset in XTS
           -> Word32     -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
           -> ba         -- ^ input to decrypt
           -> ba         -- ^ output decrypted
decryptXTS = doXTS c_aes_decrypt_xts

-- | decrypt using Galois Counter Mode (GCM)
{-# NOINLINE decryptGCM #-}
decryptGCM :: (ByteArrayAccess aad, ByteArrayAccess iv, ByteArray ba)
           => AES        -- ^ Key
           -> iv         -- ^ IV initial vector of any size
           -> aad        -- ^ data to authenticate (AAD)
           -> ba         -- ^ data to decrypt
           -> (ba, AuthTag) -- ^ plaintext and tag
decryptGCM = doGCM gcmAppendDecrypt

-- | decrypt using Offset Codebook Mode (OCB)
{-# NOINLINE decryptOCB #-}
decryptOCB :: (ByteArrayAccess aad, ByteArrayAccess iv, ByteArray ba)
           => AES        -- ^ Key
           -> iv         -- ^ IV initial vector of any size
           -> aad        -- ^ data to authenticate (AAD)
           -> ba         -- ^ data to decrypt
           -> (ba, AuthTag) -- ^ plaintext and tag
decryptOCB = doOCB ocbAppendDecrypt

{-# INLINE doECB #-}
doECB :: ByteArray ba
      => (Ptr b -> Ptr AES -> CString -> CUInt -> IO ())
      -> AES -> ba -> ba
doECB f ctx input
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16). Its length is: " ++ (show len)
    | otherwise = byteArrayAllocAndFreeze len $ \o ->
                  keyToPtr ctx $ \k ->
                  withByteArray input $ \i ->
                  f (castPtr o) k i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = byteArrayLength input

{-# INLINE doCBC #-}
doCBC :: ByteArray ba
      => (Ptr b -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ())
      -> AES -> IV AES -> ba -> ba
doCBC f ctx (IV iv) input
    | len == 0  = empty
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16). Its length is: " ++ (show len)
    | otherwise = byteArrayAllocAndFreeze len $ \o ->
                  withKeyAndIV ctx iv $ \k v ->
                  withByteArray input $ \i ->
                  f (castPtr o) k v i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = byteArrayLength input

{-# INLINE doXTS #-}
doXTS :: ByteArray ba
      => (Ptr b -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ())
      -> (AES, AES)
      -> IV AES
      -> Word32
      -> ba
      -> ba
doXTS f (key1,key2) iv spoint input
    | len == 0  = empty
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16) for now. Its length is: " ++ (show len)
    | otherwise = byteArrayAllocAndFreeze len $ \o -> withKey2AndIV key1 key2 iv $ \k1 k2 v -> withByteArray input $ \i ->
            f (castPtr o) k1 k2 v (fromIntegral spoint) i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = byteArrayLength input

------------------------------------------------------------------------
-- GCM
------------------------------------------------------------------------

{-# INLINE doGCM #-}
doGCM :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArray ba)
      => (AES -> AESGCM -> ba -> (ba, AESGCM))
      -> AES
      -> iv
      -> aad
      -> ba
      -> (ba, AuthTag)
doGCM f ctx iv aad input = (output, tag)
  where tag             = gcmFinish ctx after 16
        (output, after) = f ctx afterAAD input
        afterAAD        = gcmAppendAAD ini aad
        ini             = gcmInit ctx iv

-- | initialize a gcm context
{-# NOINLINE gcmInit #-}
gcmInit :: ByteArrayAccess iv => AES -> iv -> AESGCM
gcmInit ctx iv = unsafePerformIO $ do
    sm <- createSecureMem sizeGCM $ \gcmStPtr ->
            withKeyAndIV ctx iv $ \k v ->
            c_aes_gcm_init (castPtr gcmStPtr) k v (fromIntegral $ byteArrayLength iv)
    return $ AESGCM sm

-- | append data which is going to just be authentified to the GCM context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE gcmAppendAAD #-}
gcmAppendAAD :: ByteArrayAccess aad => AESGCM -> aad -> AESGCM
gcmAppendAAD gcmSt input = unsafePerformIO doAppend
  where doAppend =
            withNewGCMSt gcmSt $ \gcmStPtr ->
            withByteArray input $ \i ->
            c_aes_gcm_aad gcmStPtr i (fromIntegral $ byteArrayLength input)

-- | append data to encrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendEncrypt #-}
gcmAppendEncrypt :: ByteArray ba => AES -> AESGCM -> ba -> (ba, AESGCM)
gcmAppendEncrypt ctx gcm input = unsafePerformIO $ withGCMKeyAndCopySt ctx gcm doEnc
  where len = byteArrayLength input
        doEnc gcmStPtr aesPtr =
            byteArrayAlloc len $ \o ->
            withByteArray input $ \i ->
            c_aes_gcm_encrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendDecrypt #-}
gcmAppendDecrypt :: ByteArray ba => AES -> AESGCM -> ba -> (ba, AESGCM)
gcmAppendDecrypt ctx gcm input = unsafePerformIO $ withGCMKeyAndCopySt ctx gcm doDec
  where len = byteArrayLength input
        doDec gcmStPtr aesPtr =
            byteArrayAlloc len $ \o ->
            withByteArray input $ \i ->
            c_aes_gcm_decrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from GCM context
{-# NOINLINE gcmFinish #-}
gcmFinish :: AES -> AESGCM -> Int -> AuthTag
gcmFinish ctx gcm taglen = AuthTag $ B.take taglen computeTag
  where computeTag = unsafeCreate 16 $ \t ->
                        withGCMKeyAndCopySt ctx gcm (c_aes_gcm_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
-- OCB v3
------------------------------------------------------------------------

{-# INLINE doOCB #-}
doOCB :: (ByteArrayAccess iv, ByteArrayAccess aad, ByteArray ba)
      => (AES -> AESOCB -> ba -> (ba, AESOCB))
      -> AES
      -> iv
      -> aad
      -> ba
      -> (ba, AuthTag)
doOCB f ctx iv aad input = (output, tag)
  where tag             = ocbFinish ctx after 16
        (output, after) = f ctx afterAAD input
        afterAAD        = ocbAppendAAD ctx ini aad
        ini             = ocbInit ctx iv

-- | initialize an ocb context
{-# NOINLINE ocbInit #-}
ocbInit :: ByteArrayAccess iv => AES -> iv -> AESOCB
ocbInit ctx iv = unsafePerformIO $ do
    sm <- createSecureMem sizeOCB $ \ocbStPtr ->
            withKeyAndIV ctx iv $ \k v ->
            c_aes_ocb_init (castPtr ocbStPtr) k v (fromIntegral $ byteArrayLength iv)
    return $ AESOCB sm

-- | append data which is going to just be authentified to the OCB context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE ocbAppendAAD #-}
ocbAppendAAD :: ByteArrayAccess aad => AES -> AESOCB -> aad -> AESOCB
ocbAppendAAD ctx ocb input = unsafePerformIO (snd `fmap` withOCBKeyAndCopySt ctx ocb doAppend)
  where doAppend ocbStPtr aesPtr =
            withByteArray input $ \i ->
            c_aes_ocb_aad ocbStPtr aesPtr i (fromIntegral $ byteArrayLength input)

-- | append data to encrypt and append to the OCB context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendEncrypt #-}
ocbAppendEncrypt :: ByteArray ba => AES -> AESOCB -> ba -> (ba, AESOCB)
ocbAppendEncrypt ctx ocb input = unsafePerformIO $ withOCBKeyAndCopySt ctx ocb doEnc
  where len = byteArrayLength input
        doEnc ocbStPtr aesPtr =
            byteArrayAlloc len $ \o ->
            withByteArray input $ \i ->
            c_aes_ocb_encrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the OCB context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendDecrypt #-}
ocbAppendDecrypt :: ByteArray ba => AES -> AESOCB -> ba -> (ba, AESOCB)
ocbAppendDecrypt ctx ocb input = unsafePerformIO $ withOCBKeyAndCopySt ctx ocb doDec
  where len = byteArrayLength input
        doDec ocbStPtr aesPtr =
            byteArrayAlloc len $ \o ->
            withByteArray input $ \i ->
            c_aes_ocb_decrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from OCB context
{-# NOINLINE ocbFinish #-}
ocbFinish :: AES -> AESOCB -> Int -> AuthTag
ocbFinish ctx ocb taglen = AuthTag $ B.take taglen computeTag
  where computeTag = unsafeCreate 16 $ \t ->
                        withOCBKeyAndCopySt ctx ocb (c_aes_ocb_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
foreign import ccall "cryptonite_aes.h cryptonite_aes_initkey"
    c_aes_init :: Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_cbc"
    c_aes_encrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_cbc"
    c_aes_decrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_xts"
    c_aes_encrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_decrypt_xts"
    c_aes_decrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gen_ctr"
    c_aes_gen_ctr :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_aes.h cryptonite_aes_gen_ctr_cont"
    c_aes_gen_ctr_cont :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_encrypt_ctr"
    c_aes_encrypt_ctr :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_init"
    c_aes_gcm_init :: Ptr AESGCM -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_aad"
    c_aes_gcm_aad :: Ptr AESGCM -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_encrypt"
    c_aes_gcm_encrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_decrypt"
    c_aes_gcm_decrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr AESGCM -> Ptr AES -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_init"
    c_aes_ocb_init :: Ptr AESOCB -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_aad"
    c_aes_ocb_aad :: Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_encrypt"
    c_aes_ocb_encrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_decrypt"
    c_aes_ocb_decrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "cryptonite_aes.h cryptonite_aes_ocb_finish"
    c_aes_ocb_finish :: CString -> Ptr AESOCB -> Ptr AES -> IO ()

