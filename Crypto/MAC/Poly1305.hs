{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.MAC.Poly1305
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Poly1305 implementation
--
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

import Control.Monad (void)
import Foreign.Ptr
import Foreign.C.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.ByteString (ByteString)
import Data.Word
import Data.Byteable
import System.IO.Unsafe
import Data.SecureMem

-- | Poly1305 Context
newtype Ctx = Ctx SecureMem

-- | Poly1305 Auth
newtype Auth = Auth ByteString

instance Eq Auth where
    (Auth a1) == (Auth a2) = constEqBytes a1 a2
instance Byteable Auth where
    toBytes (Auth b) = b

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_init"
    c_poly1305_init :: Ptr Ctx -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_poly1305.h cryptonite_poly1305_update"
    c_poly1305_update :: Ptr Ctx -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_finalize"
    c_poly1305_finalize :: Ptr Word8 -> Ptr Ctx -> IO ()

-- | initialize a Poly1305 context
initialize :: Byteable key
     => key
     -> Ctx
initialize key
    | byteableLength key /= 32 = error "Poly1305: key length expected 32 bytes"
    | otherwise          = Ctx $ unsafePerformIO $ do
        withBytePtr key $ \keyPtr ->
            createSecureMem 84 $ \ctxPtr ->
                c_poly1305_init (castPtr ctxPtr) keyPtr
{-# NOINLINE initialize #-}

-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update (Ctx prevCtx) d = unsafePerformIO $ do
    ctx <- secureMemCopy prevCtx
    withSecureMemPtr ctx $ \ctxPtr ->
        withBytePtr d $ \dataPtr ->
            c_poly1305_update (castPtr ctxPtr) dataPtr (fromIntegral $ B.length d)
    return $ Ctx ctx
{-# NOINLINE update #-}

-- | updates a context with multiples bytestring
updates :: Ctx -> [ByteString] -> Ctx
updates (Ctx prevCtx) d = unsafePerformIO $ do
    ctx <- secureMemCopy prevCtx
    withSecureMemPtr ctx (loop d . castPtr)
    return $ Ctx ctx
  where loop []     _      = return ()
        loop (x:xs) ctxPtr = do
            withBytePtr x $ \dataPtr -> c_poly1305_update ctxPtr dataPtr (fromIntegral $ B.length x)
            loop xs ctxPtr
{-# NOINLINE updates #-}

-- | finalize the context into a digest bytestring
finalize :: Ctx -> Auth
finalize (Ctx prevCtx) = Auth $ B.unsafeCreate 16 $ \dst -> do
    ctx <- secureMemCopy prevCtx
    withSecureMemPtr ctx $ \ctxPtr -> c_poly1305_finalize dst (castPtr ctxPtr)
{-# NOINLINE finalize #-}

-- | One-pass authorization creation
auth :: Byteable key => key -> ByteString -> Auth
auth key d
    | byteableLength key /= 32 = error "Poly1305: key length expected 32 bytes"
    | otherwise                = Auth $ B.unsafeCreate 16 $ \dst -> do
        -- initialize the context
        void $ createSecureMem 84 $ \ctxPtr -> withBytePtr key $ \keyPtr -> do
                    c_poly1305_init (castPtr ctxPtr) keyPtr
                    withBytePtr d $ \dataPtr ->
                        c_poly1305_update (castPtr ctxPtr) dataPtr (fromIntegral $ B.length d)
                    -- finalize
                    c_poly1305_finalize dst (castPtr ctxPtr)
