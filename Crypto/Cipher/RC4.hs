{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Cipher.RC4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple implementation of the RC4 stream cipher.
-- http://en.wikipedia.org/wiki/RC4
--
-- Initial FFI implementation by Peter White <peter@janrain.com>
--
-- Reorganized and simplified to have an opaque context.
--
module Crypto.Cipher.RC4
    ( initialize
    , combine
    , generate
    , State
    ) where

import Data.Word
import Data.Byteable
import Data.SecureMem
import Foreign.Ptr
import Foreign.ForeignPtr
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Crypto.Internal.Compat

-- | The encryption state for RC4
newtype State = State SecureMem

-- | C Call for initializing the encryptor
foreign import ccall unsafe "cryptonite_rc4.h cryptonite_rc4_init"
    c_rc4_init :: Ptr Word8 -- ^ The rc4 key
               -> Word32    -- ^ The key length
               -> Ptr State -- ^ The context
               -> IO ()

foreign import ccall unsafe "cryptonite_rc4.h cryptonite_rc4_combine"
    c_rc4_combine :: Ptr State        -- ^ Pointer to the permutation
                  -> Ptr Word8      -- ^ Pointer to the clear text
                  -> Word32         -- ^ Length of the clear text
                  -> Ptr Word8      -- ^ Output buffer
                  -> IO ()

-- | RC4 context initialization.
--
-- seed the context with an initial key. the key size need to be
-- adequate otherwise security takes a hit.
initialize :: Byteable key
           => key   -- ^ The key
           -> State -- ^ The RC4 context with the key mixed in
initialize key = unsafeDoIO $ do
    st <- createSecureMem 264 $ \stPtr ->
        withBytePtr key $ \keyPtr -> c_rc4_init keyPtr (fromIntegral $ byteableLength key) (castPtr stPtr)
    return $ State st

-- | generate the next len bytes of the rc4 stream without combining
-- it to anything.
generate :: State -> Int -> (State, ByteString)
generate ctx len = combine ctx (B.replicate len 0)

-- | RC4 xor combination of the rc4 stream with an input
combine :: State               -- ^ rc4 context
        -> ByteString          -- ^ input
        -> (State, ByteString) -- ^ new rc4 context, and the output
combine (State prevSt) clearText = unsafeDoIO $ do
    outfptr <- B.mallocByteString len
    st      <- secureMemCopy prevSt
    withSecureMemPtr st $ \stPtr ->
        withForeignPtr outfptr $ \outptr ->
        withBytePtr clearText $ \clearPtr ->
            c_rc4_combine (castPtr stPtr) clearPtr (fromIntegral len) outptr
    return $! (State st, B.PS outfptr 0 len)
  where len = B.length clearText
