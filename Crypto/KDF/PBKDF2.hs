{-# LANGUAGE BangPatterns       #-}
-- |
-- Module      : Crypto.KDF.PBKDF2
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Password Based Key Derivation Function 2
--
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
import qualified Data.ByteString.Internal as B (unsafeCreate, memset)
import Data.Byteable
import Foreign.Storable
import Foreign.Ptr (Ptr, plusPtr)
import Control.Applicative
import Control.Monad (forM_, void)

import Crypto.Hash (HashAlgorithm)
import qualified Crypto.MAC.HMAC as HMAC

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
        hmacIncr _ !ctx = \b -> toBytes $ HMAC.finalize $ HMAC.update ctx b

-- | Parameters for PBKDF2
data Parameters = Parameters
    { password     :: ByteString
    , salt         :: ByteString
    , iterCounts   :: Int
    , outputLength :: Int
    }

-- | generate the pbkdf2 key derivation function from the output
generate :: PRF -> Parameters -> B.ByteString
generate prf params =
    B.take (outputLength params) $ B.concat $ map f [1..l]
  where
    !runPRF = prf (password params)
    !hLen   = B.length $ runPRF B.empty
    
    -- f(pass,salt,c,i) = U1 xor U2 xor .. xor Uc
    -- U1 = PRF(pass,salt || BE32(i))
    -- Uc = PRF(pass,Uc-1)
    f iterNb   = B.unsafeCreate hLen $ \dst -> do
        let applyMany 0 _     = return ()
            applyMany i uprev =
                let u = runPRF uprev
                 in bsXor dst u >> applyMany (i-1) u
        void $ B.memset dst 0 (fromIntegral hLen)
        applyMany (iterCounts params) (salt params `B.append` toBS iterNb)

    -- a mutable version of xor, that allow to not reallocate
    -- the accumulate buffer.
    bsXor :: Ptr Word8 -> ByteString -> IO ()
    bsXor d sBs = withBytePtr sBs $ \s ->
        forM_ [0..hLen-1] $ \i -> do
            v <- xor <$> peek (s `plusPtr` i) <*> peek (d `plusPtr` i)
            poke (d `plusPtr` i) (v :: Word8)

    -- count the number of blocks necessary
    l = let (q,rema) = (outputLength params) `divMod` hLen
         in fromIntegral (q + if rema > 0 then 1 else 0)
    
    -- big endian encoding of Word32
    toBS :: Word32 -> ByteString
    toBS w = B.pack [a,b,c,d]
      where a = fromIntegral (w `shiftR` 24)
            b = fromIntegral ((w `shiftR` 16) .&. 0xff)
            c = fromIntegral ((w `shiftR` 8) .&. 0xff)
            d = fromIntegral (w .&. 0xff)
