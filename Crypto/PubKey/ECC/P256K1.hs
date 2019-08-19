{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.PubKey.ECC.P256K1
  (Point(..),
   Scalar(..),
   scalarGenerate,
   toPoint,
   pointToBinary,
   pointFromBinary,
   pointAdd,
   pointNegate,
   pointMul,
   pointDh,
   parseDer,
   rfc6979,
  ) where

--import Crypto.Internal.Imports
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)
import Control.Monad (unless)
import Data.ByteArray (ByteArrayAccess, ByteArray, ScrubbedBytes, convert)
import Crypto.Random (MonadRandom, getRandomBytes)
import Crypto.Random.Entropy (getEntropy)
import Control.DeepSeq (NFData)
import Crypto.Error.Types (CryptoFailable(..), CryptoError(..),)
import Foreign.C
import Foreign
import Data.ByteString.Short (ShortByteString, toShort, fromShort)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Crypto.PubKey.ECC.ECDSA (Signature(Signature), PrivateKey(PrivateKey))
import Crypto.Hash (Digest)
import Crypto.Number.Serialize (os2ip, i2osp)
import Crypto.Hash.Algorithms (SHA256(SHA256))
import Data.ByteString.Base16 as B16
import Data.ByteString.Char8 (pack)

newtype Scalar = Scalar (ForeignPtr Bytes32)
-- Scalar ScrubbedBytes
--    deriving (Show,Eq,ByteArrayAccess,NFData)

newtype Point = Point (ForeignPtr Bytes64)

-- private key to public key
-- Based on derivePubKey
toPoint :: Scalar -> Point
toPoint (Scalar fk) = withContext $ \ctx -> withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not compute public key"
    return $ Point fp
pointAdd :: Point -> Point -> Point
pointAdd = undefined
pointNegate :: Point -> Point
pointNegate = undefined
pointMul :: Scalar -> Point -> Point
pointMul = undefined
scalarGenerate :: MonadRandom randomly => randomly Scalar
scalarGenerate = do
    bs <- getRandomBytes 32
    let ret = thirtyTwoByteStringToKey bs
    case ret of
      Nothing -> scalarGenerate
      Just x -> return x

-- based on secKey
thirtyTwoByteStringToKey :: ByteString -> Maybe Scalar
thirtyTwoByteStringToKey bs =
    withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p -> do
            poke p (Bytes32 (toShort bs))
            ecSecKeyVerify ctx p
        if isSuccess ret
            then return $ Just $ Scalar fp
            else return Nothing

-- based on importPubKey
pointFromBinary :: ByteArrayAccess ba => ba -> CryptoFailable Point
pointFromBinary ba = do
  let bs = convert ba
  withContext $ \ctx -> useByteString bs $ \(b, l) -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyParse ctx p b l
    if isSuccess ret then
      return $ CryptoPassed $ Point fp
    else
      return $ CryptoFailed CryptoError_PointCoordinatesInvalid

-- | Based on exportPubKey
pointToBinary :: ByteArray bs1 => Point -> bs1
pointToBinary (Point ptr) = withContext $ \ctx ->
    withForeignPtr ptr $ \p -> alloca $ \l -> allocaBytes z $ \o -> do
        poke l (fromIntegral z)
        ret <- ecPubKeySerialize ctx o l p c
        unless (isSuccess ret) $ error "could not serialize public key"
        n <- peek l
        bs <- packByteString (o, n)
        return $ convert bs
  where
    c = 0x0102 :: CUInt -- compressed
    z = 33 -- length of compressed pubkey

data Ctx = Ctx

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubKeySerialize
    :: Ptr Ctx
    -> Ptr CUChar -- ^ array for encoded public key, must be large enough
    -> Ptr CSize  -- ^ size of encoded public key, will be updated
    -> Ptr Bytes64 -- pubkey
    -> CUInt -- context flags
    -> IO CInt

{-# NOINLINE fctx #-}
fctx :: ForeignPtr Ctx
fctx = unsafePerformIO $ do
    x <- contextCreate 0x0301 -- signVerify
    e <- getEntropy 32
    ret <- alloca $ \s -> poke s (Bytes32 (toShort e)) >> contextRandomize x s
    unless (isSuccess ret) $ error "failed to randomize context"
    newForeignPtr contextDestroy x

{-# INLINE withContext #-}
withContext :: (Ptr Ctx -> IO a) -> a
withContext f = unsafeDupablePerformIO (withForeignPtr fctx f)

isSuccess :: CInt -> Bool
isSuccess (CInt 0) = False
isSuccess (CInt 1) = True
isSuccess _       = undefined

packByteString (b, l) = BS.packCStringLen (castPtr b, fromIntegral l)

foreign import ccall
    "secp256k1.h secp256k1_context_randomize"
    contextRandomize
    :: Ptr Ctx
    -> Ptr Bytes32
    -> IO CInt

newtype Bytes64 = Bytes64 { getBytes64 :: ShortByteString }
    deriving (Read, Show, Eq, Ord)

instance Storable Bytes64 where
    sizeOf _ = 64
    alignment _ = 1
    peek p = Bytes64 . toShort <$> packByteString (castPtr p, 64)
    poke p (Bytes64 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 64

newtype Bytes32 = Bytes32 { getBytes32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord)

instance Storable Bytes32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Bytes32 . toShort <$> packByteString (castPtr p, 32)
    poke p (Bytes32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

foreign import ccall
    "secp256k1.h secp256k1_context_create"
    contextCreate
    :: CUInt -- ctx flags
    -> IO (Ptr Ctx)

foreign import ccall
    "secp256k1.h &secp256k1_context_destroy"
    contextDestroy
    :: FunPtr (Ptr Ctx -> IO ())

useByteString :: ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) -> f (castPtr b, fromIntegral l)

instance Eq Point where
  a == b = (pointToBinary a :: ByteString) == pointToBinary b

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubKeyCreate
    :: Ptr Ctx
    -> Ptr Bytes64 --Point
    -> Ptr Bytes32 --Scalar
    -> IO CInt

foreign import ccall
    "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify
    :: Ptr Ctx
    -> Ptr Bytes32 --Scalar
    -> IO CInt

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubKeyParse
    :: Ptr Ctx
    -> Ptr Bytes64 -- pubkey
    -> Ptr CUChar -- ^ encoded public key array
    -> CSize      -- ^ size of encoded public key array
    -> IO CInt

foreign import ccall
    "secp256k1.h secp256k1_ecdh"
    ecEcdh
    :: Ptr Ctx
    -> Ptr CUChar -- output (32 bytes)
    -> Ptr Bytes64 -- pubkey
    -> Ptr Bytes32 -- privkey
    -> Ptr Int -- hash function pointer. int is just bogus
    -> Ptr CUChar -- arbitrary data that is passed through
    -> IO CInt

pointDh :: ByteArray binary => Scalar -> Point -> binary
pointDh (Scalar sfp) (Point pfp) =
  withContext $ \ctx ->
    withForeignPtr sfp $ \p ->
      withForeignPtr pfp $ \s ->
        allocaBytes 32 $ \o -> do
          ret <- ecEcdh ctx o s p nullPtr nullPtr
          unless (isSuccess ret) $ error "scalar was invalid\
                                         \(zero or overflow)"
          bs <- packByteString (o, 32)
          return $ convert bs

-- stolen from secp256k1-haskell test suite
parseDer :: ByteString -> Maybe Signature
parseDer bs =
  withContext $ \ctx ->
    BS.useAsCStringLen bs $ \(d, dl) -> alloca $ \s -> do
      ret <- ecdsaSignatureParseDer ctx s (castPtr d) (fromIntegral dl)
      if isSuccess ret then do
        b64 <- peek s
        let (r, s) = BS.splitAt 32 $ fromShort $ getBytes64 b64
        return $ Just $ Signature (os2ip r) (os2ip s)
      else do
        return Nothing

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer
    :: Ptr Ctx
    -> Ptr Bytes64
    -> Ptr CUChar -- ^ encoded DER signature
    -> CSize      -- ^ size of encoded signature
    -> IO CInt

-- counter (Int) is included here because signing
-- could fail with the returned k
-- see src/secp256k1.c revision e541a90 line 475
rfc6979 :: Digest SHA256 -> PrivateKey -> CUInt -> Integer 
rfc6979 digest (PrivateKey _ pk) counter =
  unsafePerformIO $ do
    let digestbs = fst $ B16.decode $ pack $ show digest
    unless (32 == BS.length digestbs) $ error "digest length wrong"
    fpd <- mallocForeignPtr
    withForeignPtr fpd $ \digest32 -> do
      poke digest32 (Bytes32 (toShort digestbs))
      fpk <- mallocForeignPtr
      withForeignPtr fpk $ \key32 -> do
        poke key32 (Bytes32 (toShort (i2osp pk)))
        fp <- mallocForeignPtr
        withForeignPtr fp $ \nonce32 -> do
        --allocaBytes 32 $ \nonce32 -> do
          --allocaBytes 32 $ \nonceScalar -> do
            --alloca $ \overflow -> do
              res <- secp256k1_rfc6979 nonce32 digest32 key32 nullPtr nullPtr counter
              unless (isSuccess res) $ error "rfc6979 nonce function failed"
              --scalar_set nonceScalar nonce32 overflow
              --n <- peek overflow
              --unless (CInt 0 == n) $ error "rfc6979 nonce fun returned\
              --                                    \overflowing scalar"
              --is_zero <- scalar_is_zero nonceScalar
              --unless (isSuccess is_zero) $ error "rfc6979 nonce fun returned\
              --                                   \zero scalar"
              bs <- packByteString (nonce32, 32)
              return $ os2ip $ bs

foreign import ccall
  "secp256k1.h secp256k1_nonce_function_rfc6979"
  secp256k1_rfc6979
  :: Ptr Bytes32 -- nonce output (32 bytes)
  -> Ptr Bytes32 -- msg hash input (32 bytes)
  -> Ptr Bytes32 -- key input (32 bytes)
  -> Ptr CUChar -- algo (can be null)
  -> Ptr CUChar -- data void pointer (can be null)
  -> CUInt
  -> IO CInt

--foreign import ccall
--  "secp256k1.h secp256k1_scalar_set_b32"
--  scalar_set
--  :: Ptr Bytes32 -- secp256k1_scalar pointer (output)
--  -> Ptr CUChar -- 32 bytes (input)
--  -> Ptr CInt -- overflow (output)
--  -> IO ()
--
--foreign import ccall
--  "secp256k1.h secp256k1_scalar_is_zero"
--  scalar_is_zero
--  :: Ptr Bytes32 -- secp256k1_scalar pointer (input)
--  -> IO CInt
