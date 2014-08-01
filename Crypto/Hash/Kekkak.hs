{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Hash.Kekkak
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- module containing the basic functions to work with the
-- Kekkak cryptographic hash.
--
module Crypto.Hash.Kekkak
    ( Ctx(..)

    -- * Incremental hashing Functions
    , init     -- :: Int -> Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: Int -> ByteString -> ByteString
    , hashlazy -- :: Int -> ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr)
import Data.Word
import Crypto.Hash.Internal (unsafeDoIO)

-- | Kekkak Context.
newtype Ctx = Ctx ByteString

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 360

{- return the number of bytes of output for the digest -}
peekHashlen :: Ptr Ctx -> IO Int
peekHashlen ptr = peek iptr >>= \v -> return $! fromIntegral v
    where iptr :: Ptr Word32
          iptr = castPtr ptr

{-# RULES "hash" forall b i. finalize (update (init i) b) = hash i b #-}
{-# RULES "hash.list1" forall b i. finalize (updates (init i) [b]) = hash i b #-}
{-# RULES "hashmany" forall b i. finalize (foldl update (init i) b) = hashlazy i (L.fromChunks b) #-}
{-# RULES "hashlazy" forall b i. finalize (foldl update (init i) $ L.toChunks b) = hashlazy i b #-}

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

{-# INLINE memcopy64 #-}
memcopy64 :: Ptr Word64 -> Ptr Word64 -> IO ()
memcopy64 dst src = mapM_ peekAndPoke [0..(45-1)]
    where peekAndPoke i = peekElemOff src i >>= pokeElemOff dst i

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx ctxB) f = Ctx `fmap` createCtx
    where createCtx = create sizeCtx $ \dstPtr ->
                      withByteStringPtr ctxB $ \srcPtr -> do
                          memcopy64 (castPtr dstPtr) (castPtr srcPtr)
                          f (castPtr dstPtr)

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx ctxB) f =
    allocaBytes sizeCtx $ \dstPtr ->
    withByteStringPtr ctxB $ \srcPtr -> do
        memcopy64 (castPtr dstPtr) (castPtr srcPtr)
        f (castPtr dstPtr)

withCtxNew :: (Ptr Ctx -> IO ()) -> IO Ctx
withCtxNew f = Ctx `fmap` create sizeCtx (f . castPtr)

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = allocaBytes sizeCtx (f . castPtr)

foreign import ccall unsafe "cryptonite_kekkak.h cryptonite_kekkak_init"
    c_kekkak_init :: Ptr Ctx -> Word32 -> IO ()

foreign import ccall "cryptonite_kekkak.h cryptonite_kekkak_update"
    c_kekkak_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "cryptonite_kekkak.h cryptonite_kekkak_finalize"
    c_kekkak_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_kekkak_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
    peekHashlen ptr >>= \digestSize -> create digestSize (c_kekkak_finalize ptr)

{-# NOINLINE init #-}
-- | init a context where
init :: Int -- ^ algorithm hash size in bits
     -> Ctx
init hashlen = unsafeDoIO $ withCtxNew $ \ptr -> c_kekkak_init ptr (fromIntegral hashlen)

{-# NOINLINE update #-}
-- | update a context with a bytestring returning the new updated context
update :: Ctx        -- ^ the context to update
       -> ByteString -- ^ the data to update with
       -> Ctx        -- ^ the updated context
update ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d

{-# NOINLINE updates #-}
-- | updates a context with multiples bytestring returning the new updated context
updates :: Ctx          -- ^ the context to update
        -> [ByteString] -- ^ a list of data bytestring to update with
        -> Ctx          -- ^ the updated context
updates ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (updateInternalIO ptr) d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: Int        -- ^ algorithm hash size in bits
     -> ByteString -- ^ the data to hash
     -> ByteString -- ^ the digest output
hash hashlen d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_kekkak_init ptr (fromIntegral hashlen) >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int          -- ^ algorithm hash size in bits
         -> L.ByteString -- ^ the data to hash as a lazy bytestring
         -> ByteString   -- ^ the digest output
hashlazy hashlen l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_kekkak_init ptr (fromIntegral hashlen) >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
