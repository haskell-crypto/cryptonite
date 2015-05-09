-- |
-- Module      : Crypto.KDF.PBKDF2
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Password Based Key Derivation Function 2
--
{-# LANGUAGE BangPatterns #-}
module Crypto.KDF.PBKDF2
    ( PRF
    , prfHMAC
    , Parameters(..)
    , generate
    ) where

import Data.Word
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Foreign.Marshal.Alloc
import Foreign.Ptr (plusPtr)

import Crypto.Hash (HashAlgorithm)
import qualified Crypto.MAC.HMAC as HMAC

import           Crypto.Internal.ByteArray (ByteArray)
import qualified Crypto.Internal.ByteArray as B (allocAndFreeze, convert, withByteArray)
import           Data.Memory.PtrMethods

-- | The PRF used for PBKDF2
type PRF = B.ByteString -- ^ the password parameters
        -> B.ByteString -- ^ the content
        -> B.ByteString -- ^ prf(password,content)

-- | PRF for PBKDF2 using HMAC with the hash algorithm as parameter
prfHMAC :: HashAlgorithm a
        => a   -- ^ the Hash Algorithm to use with HMAC
        -> PRF -- ^ the PRF functiont o use
prfHMAC alg k = hmacIncr alg (HMAC.initialize k)
  where hmacIncr :: HashAlgorithm a => a -> HMAC.Context a -> (ByteString -> ByteString)
        hmacIncr _ !ctx = \b -> B.convert $ HMAC.finalize $ HMAC.update ctx b

-- | Parameters for PBKDF2
data Parameters = Parameters
    { password     :: ByteString -- ^ Password (bytes encoded)
    , salt         :: ByteString -- ^ Salt (bytes encoded)
    , iterCounts   :: Int        -- ^ the number of user-defined iterations for the algorithms. e.g. WPA2 uses 4000.
    , outputLength :: Int        -- ^ the number of bytes to generate out of PBKDF2
    }

-- | generate the pbkdf2 key derivation function from the output
generate :: ByteArray ba => PRF -> Parameters -> ba
generate prf params =
    B.allocAndFreeze (outputLength params) $ \p -> do
        memSet p 0 (outputLength params)
        loop 1 (outputLength params) p
  where
    !runPRF = prf (password params)
    !hLen   = B.length $ runPRF B.empty

    -- run the following f function on each complete chunk.
    -- when having an incomplete chunk, we call partial.
    -- partial need to be the last call.
    --
    -- f(pass,salt,c,i) = U1 xor U2 xor .. xor Uc
    -- U1 = PRF(pass,salt || BE32(i))
    -- Uc = PRF(pass,Uc-1)
    loop iterNb len p
        | len == 0   = return ()
        | len < hLen = partial iterNb len p
        | otherwise  = do
            let applyMany 0 _     = return ()
                applyMany i uprev = do
                    let uData = runPRF uprev
                    B.withByteArray uData $ \u -> memXor p p u hLen
                    applyMany (i-1) uData
            applyMany (iterCounts params) (salt params `B.append` toBS iterNb)
            loop (iterNb+1) (len - hLen) (p `plusPtr` hLen)

    partial iterNb len p = allocaBytesAligned hLen 8 $ \tmp -> do
        let applyMany 0 _     = return ()
            applyMany i uprev = do
                let uData = runPRF uprev
                B.withByteArray uData $ \u -> memXor tmp tmp u hLen
                applyMany (i-1) uData
        memSet tmp 0 hLen
        applyMany (iterCounts params) (salt params `B.append` toBS iterNb)
        memCopy p tmp len

    -- big endian encoding of Word32
    toBS :: Word32 -> ByteString
    toBS w = B.pack [a,b,c,d]
      where a = fromIntegral (w `shiftR` 24)
            b = fromIntegral ((w `shiftR` 16) .&. 0xff)
            c = fromIntegral ((w `shiftR` 8) .&. 0xff)
            d = fromIntegral (w .&. 0xff)
{-# NOINLINE generate #-}
