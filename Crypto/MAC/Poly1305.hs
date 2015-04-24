
-- |
-- Module      : Crypto.MAC.Poly1305
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Poly1305 implementation
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.MAC.Poly1305
    ( Ctx
    , Auth(..)

    -- * Incremental MAC Functions
    , initialize -- :: Ctx
    , update     -- :: Ctx -> ByteString -> Ctx
    , updates    -- :: Ctx -> [ByteString] -> Ctx
    , finalize   -- :: Ctx -> Auth
    -- * One-pass MAC function
    , auth
    ) where

import           Foreign.Ptr
import           Foreign.C.Types
import           Data.Word
import           Crypto.Internal.ByteArray (ByteArrayAccess, SecureBytes, Bytes)
import qualified Crypto.Internal.ByteArray as B

-- | Poly1305 Context
newtype Ctx = Ctx SecureBytes
    deriving (ByteArrayAccess)

-- | Poly1305 Auth
newtype Auth = Auth Bytes
    deriving (ByteArrayAccess)

instance Eq Auth where
    (Auth a1) == (Auth a2) = B.constEq a1 a2

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_init"
    c_poly1305_init :: Ptr Ctx -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_poly1305.h cryptonite_poly1305_update"
    c_poly1305_update :: Ptr Ctx -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_finalize"
    c_poly1305_finalize :: Ptr Word8 -> Ptr Ctx -> IO ()

-- | initialize a Poly1305 context
initialize :: ByteArrayAccess key
           => key
           -> Ctx
initialize key
    | B.length key /= 32 = error "Poly1305: key length expected 32 bytes"
    | otherwise          = Ctx $ B.allocAndFreeze 84 $ \ctxPtr ->
        B.withByteArray key $ \keyPtr ->
            c_poly1305_init (castPtr ctxPtr) keyPtr
{-# NOINLINE initialize #-}

-- | update a context with a bytestring
update :: ByteArrayAccess ba => Ctx -> ba -> Ctx
update (Ctx prevCtx) d = Ctx $ B.copyAndFreeze prevCtx $ \ctxPtr ->
    B.withByteArray d $ \dataPtr ->
        c_poly1305_update (castPtr ctxPtr) dataPtr (fromIntegral $ B.length d)
{-# NOINLINE update #-}

-- | updates a context with multiples bytestring
updates :: ByteArrayAccess ba => Ctx -> [ba] -> Ctx
updates (Ctx prevCtx) d = Ctx $ B.copyAndFreeze prevCtx (loop d)
  where loop []     _      = return ()
        loop (x:xs) ctxPtr = do
            B.withByteArray x $ \dataPtr -> c_poly1305_update ctxPtr dataPtr (fromIntegral $ B.length x)
            loop xs ctxPtr
{-# NOINLINE updates #-}

-- | finalize the context into a digest bytestring
finalize :: Ctx -> Auth
finalize (Ctx prevCtx) = Auth $ B.allocAndFreeze 16 $ \dst -> do
    _ <- B.copy prevCtx (\ctxPtr -> c_poly1305_finalize dst (castPtr ctxPtr)) :: IO SecureBytes
    return ()
{-# NOINLINE finalize #-}

-- | One-pass authorization creation
auth :: (ByteArrayAccess key, ByteArrayAccess ba) => key -> ba -> Auth
auth key d
    | B.length key /= 32 = error "Poly1305: key length expected 32 bytes"
    | otherwise          = Auth $ B.allocAndFreeze 16 $ \dst -> do
        _ <- B.alloc 84 (onCtx dst) :: IO SecureBytes
        return ()
  where
        onCtx dst ctxPtr =
            B.withByteArray key $ \keyPtr -> do
                c_poly1305_init (castPtr ctxPtr) keyPtr
                B.withByteArray d $ \dataPtr ->
                    c_poly1305_update (castPtr ctxPtr) dataPtr (fromIntegral $ B.length d)
                c_poly1305_finalize dst (castPtr ctxPtr)
