-- |
-- Module      : Crypto.Random.Entropy.Windows
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- code originally from the entropy package and thus is:
--   Copyright (c) Thomas DuBuisson.
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Random.Entropy.Windows
    ( WinCryptoAPI
    ) where

import Data.Int (Int32)
import Data.Word (Word32, Word8)
import Foreign.C.String (CString, withCString)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (toBool)
import Foreign.Storable (peek)

import Crypto.Random.Entropy.Source

-- Define the constants we need from WinCrypt.h 
msDefProv :: String
msDefProv = "Microsoft Base Cryptographic Provider v1.0"

provRSAFull :: Word32
provRSAFull = 1

cryptVerifyContext :: Word32
cryptVerifyContext = 0xF0000000

-- | handle to windows crypto API for random generation
data WinCryptoAPI = WinCryptoAPI

instance EntropySource WinCryptoAPI where
    entropyOpen = do
        mctx <- cryptAcquireCtx
        maybe (return Nothing) (\ctx -> cryptReleaseCtx ctx >> return (Just WinCryptoAPI)) mctx
    entropyGather WinCryptoAPI ptr n = do
        mctx <- cryptAcquireCtx
        case mctx of
            Nothing  -> error "cannot re-grab win crypto api"
            Just ctx -> do
                r <- cryptGenRandom ctx ptr n
                cryptReleaseCtx ctx
                return r
    entropyClose WinCryptoAPI = return ()

type CryptCtx = Word32

-- Declare the required CryptoAPI imports 
foreign import stdcall unsafe "CryptAcquireContextA"
   c_cryptAcquireCtx :: Ptr Word32 -> CString -> CString -> Word32 -> Word32 -> IO CryptCtx
foreign import stdcall unsafe "CryptGenRandom"
   c_cryptGenRandom :: CryptCtx -> Word32 -> Ptr Word8 -> IO Int32
foreign import stdcall unsafe "CryptReleaseContext"
   c_cryptReleaseCtx :: CryptCtx -> Word32 -> IO Int32

cryptAcquireCtx :: IO (Maybe CryptCtx)
cryptAcquireCtx = 
    alloca $ \handlePtr -> 
    withCString msDefProv $ \provName -> do
        r <- toBool `fmap` c_cryptAcquireCtx handlePtr nullPtr provName provRSAFull cryptVerifyContext
        if r
            then Just `fmap` peek handlePtr
            else return Nothing

cryptGenRandom :: CryptCtx -> Ptr Word8 -> Int -> IO Int
cryptGenRandom h buf n = do
    success <- toBool `fmap` c_cryptGenRandom h (fromIntegral n) buf
    return $ if success then n else 0

cryptReleaseCtx :: CryptCtx -> IO ()
cryptReleaseCtx h = do
    success <- toBool `fmap` c_cryptReleaseCtx h 0
    if success
        then return ()
        else fail "cryptReleaseCtx"
