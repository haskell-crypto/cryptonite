{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Crypto.PubKey.ECC.P256K1 (
    Point (..),
    Scalar (..),
    scalarGenerate,
    scalarToPoint,
    pointToBinary,
    pointFromBinary,
    pointDh,
    parseDer,
    rfc6979,
    pointToTPoint,
    pointFromTPoint,
    scalarFromInteger,
    scalarToBinary
) where

import Control.Monad (unless)
import Crypto.Error.Types (CryptoError (..), CryptoFailable (..), throwCryptoError)
import Crypto.Hash (Digest, SHA256)
import Crypto.Number.Serialize (i2osp, os2ip, i2ospOf)
import Crypto.PubKey.ECC.ECDSA (PrivateKey (PrivateKey), Signature (Signature))
import qualified Crypto.PubKey.ECC.Types as T
import Crypto.Random (MonadRandom, getRandomBytes)
import Crypto.Random.Entropy (getEntropy)
import Data.ByteArray (ByteArray, ByteArrayAccess, convert)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString, fromShort, toShort)
import Foreign
import Foreign.C
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)

newtype Scalar = Scalar (ForeignPtr Bytes32)

scalarToBinary :: ByteArray binary => Scalar -> binary
scalarToBinary (Scalar fk) = convert $ fromShort $ getBytes32 $ unsafePerformIO $ withForeignPtr fk peek

newtype Point = Point (ForeignPtr Bytes64)

-- private key to public key
-- Based on derivePubKey
scalarToPoint :: Scalar -> Point
scalarToPoint (Scalar fk) =
    withContext $ \ctx -> withForeignPtr fk $ \k -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p -> ecPubKeyCreate ctx p k
        unless (isSuccess ret) $ throwCryptoError $ CryptoFailed CryptoError_EcScalarOutOfBounds
        return $ Point fp

scalarGenerate :: MonadRandom randomly => randomly Scalar
scalarGenerate = do
    bs <- getRandomBytes 32
    case scalarFromInteger $ os2ip (bs :: ByteString) of
        CryptoPassed scalar -> return scalar
        CryptoFailed _ -> scalarGenerate

-- based on secKey
scalarFromInteger :: Integer -> CryptoFailable Scalar
scalarFromInteger int =
    withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <-
            withForeignPtr fp $ \p -> do
                let Just bs = i2ospOf 32 int
                poke p (Bytes32 (toShort bs))
                ecSecKeyVerify ctx p
        if isSuccess ret
            then return $ CryptoPassed $ Scalar fp
            else return $ CryptoFailed CryptoError_EcScalarOutOfBounds

-- based on importPubKey
pointFromBinary :: ByteArrayAccess ba => ba -> CryptoFailable Point
pointFromBinary ba = do
    let bs = convert ba
    withContext $ \ctx -> useByteString bs $ \(b, l) -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p -> ecPubKeyParse ctx p b l
        if isSuccess ret
            then return $ CryptoPassed $ Point fp
            else return $ CryptoFailed CryptoError_PointFormatInvalid

-- | Based on exportPubKey
pointToBinary :: ByteArray bs1 => Point -> bs1
pointToBinary (Point ptr) = withContext $ \ctx ->
    withForeignPtr ptr $ \p -> alloca $ \l -> allocaBytes z $ \o -> do
        poke l (fromIntegral z)
        ret <- ecPubKeySerialize ctx o l p c
        unless (isSuccess ret) $ throwCryptoError $ CryptoFailed CryptoError_InternalAssumptionFailed
        n <- peek l
        bs <- packByteString (o, n)
        return $ convert bs
    where
        c = 0x0102 :: CUInt -- compressed
        z = 33 -- length of compressed pubkey

data Ctx

foreign import ccall "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubKeySerialize
        :: Ptr Ctx
        -> Ptr CUChar -- ^ array for encoded public key, must be large enough
        -> Ptr CSize -- ^ size of encoded public key, will be updated
        -> Ptr Bytes64 -- pubkey
        -> CUInt -- context flags
        -> IO CInt

{-# NOINLINE fctx #-}
fctx :: ForeignPtr Ctx
fctx = unsafePerformIO $ do
    x <- contextCreate 0x0301 -- signVerify
    e <- getEntropy 32
    ret <- alloca $ \s -> poke s (Bytes32 (toShort e)) >> contextRandomize x s
    unless (isSuccess ret) $ throwCryptoError $ CryptoFailed CryptoError_InternalAssumptionFailed
    newForeignPtr contextDestroy x

{-# INLINE withContext #-}
withContext :: (Ptr Ctx -> IO a) -> a
withContext f = unsafeDupablePerformIO (withForeignPtr fctx f)

isSuccess :: CInt -> Bool
isSuccess (CInt 0) = False
isSuccess (CInt 1) = True
isSuccess _ = throwCryptoError $ CryptoFailed CryptoError_InternalAssumptionFailed

packByteString :: (Ptr a, CSize) -> IO BS.ByteString
packByteString (b, l) = BS.packCStringLen (castPtr b, fromIntegral l)

foreign import ccall "secp256k1.h secp256k1_context_randomize"
    contextRandomize
        :: Ptr Ctx
        -> Ptr Bytes32
        -> IO CInt

newtype Bytes64 = Bytes64 {getBytes64 :: ShortByteString}
    deriving (Read, Show, Eq, Ord)

instance Storable Bytes64 where
    sizeOf _ = 64
    alignment _ = 1
    peek p = Bytes64 . toShort <$> packByteString (p, 64)
    poke p (Bytes64 k) = useByteString (fromShort k)
        $ \(b, _) -> copyArray (castPtr p) b 64

newtype Bytes32 = Bytes32 {getBytes32 :: ShortByteString}
    deriving (Read, Show, Eq, Ord)

instance Storable Bytes32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Bytes32 . toShort <$> packByteString (p, 32)
    poke p (Bytes32 k) = useByteString (fromShort k)
        $ \(b, _) -> copyArray (castPtr p) b 32

foreign import ccall "secp256k1.h secp256k1_context_create"
    contextCreate
        :: CUInt -- ctx flags
        -> IO (Ptr Ctx)

foreign import ccall "secp256k1.h &secp256k1_context_destroy"
    contextDestroy :: FunPtr (Ptr Ctx -> IO ())

useByteString :: ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) -> f (castPtr b, fromIntegral l)

instance Eq Point where
    a == b = (pointToBinary a :: ByteString) == pointToBinary b

foreign import ccall "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubKeyCreate
        :: Ptr Ctx
        -> Ptr Bytes64 --Point
        -> Ptr Bytes32 --Scalar
        -> IO CInt

foreign import ccall "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify
        :: Ptr Ctx
        -> Ptr Bytes32 --Scalar
        -> IO CInt

foreign import ccall "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubKeyParse
        :: Ptr Ctx
        -> Ptr Bytes64 -- pubkey
        -> Ptr CUChar -- ^ encoded public key array
        -> CSize -- ^ size of encoded public key array
        -> IO CInt

foreign import ccall "secp256k1.h secp256k1_ecdh"
    ecEcdh
        :: Ptr Ctx
        -> Ptr Bytes32 -- output (32 bytes)
        -> Ptr Bytes64 -- pubkey
        -> Ptr Bytes32 -- privkey
        -> Ptr Int -- hash function pointer. int is just bogus
        -> Ptr CUChar -- arbitrary data that is passed through
        -> IO CInt

pointDh :: ByteArray binary => Scalar -> Point -> binary
pointDh (Scalar sfp) (Point pfp) =
    withContext $ \ctx ->
        withForeignPtr sfp $ \p ->
            withForeignPtr pfp $ \s -> do
                fp <- mallocForeignPtr
                withForeignPtr fp $ \o -> do
                    ret <- ecEcdh ctx o s p nullPtr nullPtr
                    unless (isSuccess ret)
                        $ throwCryptoError $ CryptoFailed
                            CryptoError_EcScalarOutOfBounds
                    bs <- packByteString (o, 32)
                    return $ convert bs

pointFromTPoint :: T.Point -> Point
pointFromTPoint T.PointO = throwCryptoError $ CryptoFailed CryptoError_PointCoordinatesInvalid
pointFromTPoint (T.Point x y) = withContext $ \ctx ->
    useByteString bs $ \(buf, _) -> do
        fp <- mallocForeignPtr
        withForeignPtr fp $ \p -> do
            ret <- ecPubKeyParse ctx p buf 65
            if isSuccess ret
                then return $ Point fp
                else throwCryptoError $ CryptoFailed CryptoError_InternalAssumptionFailed
    where
        Just bx = i2ospOf 32 x
        Just by = i2ospOf 32 y
        bs = BS.concat [BS.pack [0x04], bx, by]

pointToTPoint :: Point -> CryptoFailable T.Point
pointToTPoint (Point fp) = withContext $ \ctx ->
    withForeignPtr fp $ \p ->
        alloca $ \outputlen -> allocaBytes z $ \o -> do
            poke outputlen (fromIntegral z)
            ret2 <- ecPubKeySerialize ctx o outputlen p flags
            if not $ isSuccess ret2 then
                return $ CryptoFailed CryptoError_InternalAssumptionFailed
            else do
                n <- peek outputlen
                if n /= 65 then
                    return $ CryptoFailed CryptoError_InternalAssumptionFailed
                else do
                    outbs <- packByteString (o, n)
                    let (_, coords) = BS.splitAt 1 outbs
                    let (bx, by) = BS.splitAt 32 coords
                    return $ CryptoPassed $ T.Point (os2ip bx) (os2ip by)
    where
        flags = 0x0002 :: CUInt -- uncompressed
        z = 65 -- length of uncompressed pubkey

-- stolen from secp256k1-haskell test suite
parseDer :: ByteString -> CryptoFailable Signature
parseDer bs =
    withContext $ \ctx ->
        BS.useAsCStringLen bs $ \(d, dl) -> alloca $ \sigbuf -> do
            ret1 <- ecdsaSignatureParseDer ctx sigbuf (castPtr d) (fromIntegral dl)
            if isSuccess ret1
                then do
                    alloca $ \pc -> do
                        ret2 <- ecdsaSignatureSerializeCompact ctx pc sigbuf
                        unless (isSuccess ret2) $ throwCryptoError $
                            CryptoFailed CryptoError_InternalAssumptionFailed
                        b64 <- peek pc
                        let (r, s) = BS.splitAt 32 $ fromShort $ getBytes64 b64
                        return $ CryptoPassed $ Signature (os2ip r) (os2ip s)
                else do
                    return $ CryptoFailed CryptoError_SignatureInvalid

foreign import ccall "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
    ecdsaSignatureSerializeCompact
        :: Ptr Ctx
        -> Ptr Bytes64 -- output compact sig
        -> Ptr Bytes64 -- sig
        -> IO CInt

foreign import ccall "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer
        :: Ptr Ctx
        -> Ptr Bytes64
        -> Ptr CUChar -- ^ encoded DER signature
        -> CSize -- ^ size of encoded signature
        -> IO CInt

-- counter (CUInt) is included here because signing
-- could fail with the returned k
-- see src/secp256k1.c revision e541a90 line 475
rfc6979 :: Digest SHA256 -> PrivateKey -> CUInt -> Integer
rfc6979 digest (PrivateKey _ pk) counter =
    unsafePerformIO $ do
        let digestbs = convert digest
        fpd <- mallocForeignPtr
        withForeignPtr fpd $ \digest32 -> do
            poke digest32 (Bytes32 (toShort digestbs))
            fpk <- mallocForeignPtr
            withForeignPtr fpk $ \key32 -> do
                poke key32 (Bytes32 (toShort (i2osp pk)))
                fp <- mallocForeignPtr
                withForeignPtr fp $ \nonce32 -> do
                    res <- secp256k1_rfc6979 nonce32 digest32 key32 nullPtr nullPtr counter
                    unless (isSuccess res) $ throwCryptoError $ CryptoFailed CryptoError_EcScalarOutOfBounds
                    bs <- packByteString (nonce32, 32)
                    return $ os2ip $ bs

type RFC6979Fun
    = Ptr Bytes32 -- nonce output (32 bytes)
    -> Ptr Bytes32 -- msg hash input (32 bytes)
    -> Ptr Bytes32 -- key input (32 bytes)
    -> Ptr CUChar -- algo (can be null)
    -> Ptr CUChar -- data void pointer (can be null)
    -> CUInt
    -> IO CInt

foreign import capi "secp256k1.h value secp256k1_nonce_function_rfc6979"
    ptr_secp256k1_rfc6979 :: FunPtr RFC6979Fun

foreign import ccall "dynamic" mkInner :: FunPtr RFC6979Fun -> RFC6979Fun

secp256k1_rfc6979 :: RFC6979Fun
secp256k1_rfc6979 = mkInner ptr_secp256k1_rfc6979
