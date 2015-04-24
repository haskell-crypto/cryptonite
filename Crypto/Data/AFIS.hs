-- |
-- Module      : Crypto.Data.AFIS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- haskell implementation of the Anti-forensic information splitter
-- available in LUKS. <http://clemens.endorphin.org/AFsplitter>
--
-- The algorithm bloats an arbitrary secret with many bits that are necessary for
-- the recovery of the key (merge), and allow greater way to permanently
-- destroy a key stored on disk.
--
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Data.AFIS
    ( split
    , merge
    ) where

import Crypto.Hash
import Crypto.Random.Types
import Crypto.Internal.Memory (Bytes)
import Crypto.Internal.Bytes (bufSet, bufCopy)
import Crypto.Internal.Compat
import Crypto.Internal.ByteArray (withByteArray)
import Control.Monad (forM_, foldM)
import Data.Byteable
import Data.ByteString (ByteString)
import Data.Word
import Data.Bits
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr (newForeignPtr_)
import qualified Data.ByteString.Internal as B

import qualified Crypto.Internal.ByteArray as B

-- | Split data to diffused data, using a random generator and
-- an hash algorithm.
--
-- the diffused data will consist of random data for (expandTimes-1)
-- then the last block will be xor of the accumulated random data diffused by
-- the hash algorithm.
--
-- ----------
-- -  orig  -
-- ----------
--
-- ---------- ---------- --------------
-- - rand1  - - rand2  - - orig ^ acc -
-- ---------- ---------- --------------
--
-- where acc is :
--   acc(n+1) = hash (n ++ rand(n)) ^ acc(n)
--
split :: (HashAlgorithm a, DRG rng)
      => HashFunctionBS a  -- ^ Hash function to use as diffuser
      -> rng               -- ^ Random generator to use
      -> Int               -- ^ Number of times to diffuse the data.
      -> ByteString        -- ^ original data to diffuse.
      -> (ByteString, rng) -- ^ The diffused data
{-# NOINLINE split #-}
split hashF rng expandTimes src
    | expandTimes <= 1 = error "invalid expandTimes value"
    | otherwise        = unsafeDoIO $ do
        (rng', bs) <- B.allocRet diffusedLen runOp
        return (bs, rng')
  where diffusedLen = blockSize * expandTimes
        blockSize   = B.length src
        runOp dstPtr = do
            let lastBlock = dstPtr `plusPtr` (blockSize * (expandTimes-1))
            bufSet lastBlock 0 blockSize
            let randomBlockPtrs = map (plusPtr dstPtr . (*) blockSize) [0..(expandTimes-2)]
            rng' <- foldM fillRandomBlock rng randomBlockPtrs
            mapM_ (addRandomBlock lastBlock) randomBlockPtrs
            withByteArray src $ \srcPtr -> xorMem srcPtr lastBlock blockSize
            return rng'
        addRandomBlock lastBlock blockPtr = do
            xorMem blockPtr lastBlock blockSize
            diffuse hashF lastBlock blockSize
        fillRandomBlock g blockPtr = do
            let (rand :: Bytes, g') = randomBytesGenerate blockSize g
            withByteArray rand $ \randPtr -> bufCopy blockPtr randPtr (fromIntegral blockSize)
            return g'

-- | Merge previously diffused data back to the original data.
merge :: HashAlgorithm a
      => HashFunctionBS a -- ^ Hash function used as diffuser
      -> Int              -- ^ Number of times to un-diffuse the data
      -> ByteString       -- ^ Diffused data
      -> ByteString       -- ^ Original data
{-# NOINLINE merge #-}
merge hashF expandTimes bs
    | r /= 0            = error "diffused data not a multiple of expandTimes"
    | originalSize <= 0 = error "diffused data null"
    | otherwise         = B.allocAndFreeze originalSize $ \dstPtr ->
        B.withByteArray bs $ \srcPtr -> do
            bufSet dstPtr 0 originalSize
            forM_ [0..(expandTimes-2)] $ \i -> do
                xorMem (srcPtr `plusPtr` (i * originalSize)) dstPtr originalSize
                diffuse hashF dstPtr originalSize
            xorMem (srcPtr `plusPtr` ((expandTimes-1) * originalSize)) dstPtr originalSize
            return ()
  where (originalSize,r) = len `quotRem` expandTimes
        len              = B.length bs

-- | inplace Xor with an input
-- dst = src `xor` dst
xorMem :: Ptr Word8 -> Ptr Word8 -> Int -> IO ()
xorMem src dst sz
    | sz `mod` 64 == 0 = loop 8 (castPtr src :: Ptr Word64) (castPtr dst) sz
    | sz `mod` 32 == 0 = loop 4 (castPtr src :: Ptr Word32) (castPtr dst) sz
    | otherwise        = loop 1 (src :: Ptr Word8) dst sz
  where loop _    _ _ 0 = return ()
        loop incr s d n = do a <- peek s
                             b <- peek d
                             poke d (a `xor` b)
                             loop incr (s `plusPtr` incr) (d `plusPtr` incr) (n-incr)

diffuse :: HashAlgorithm a
        => HashFunctionBS a -- ^ Hash function to use as diffuser
        -> Ptr Word8
        -> Int
        -> IO ()
diffuse hashF src sz = loop src 0
  where (full,pad) = sz `quotRem` digestSize 
        loop s i | i < full = do h <- hashBlock i `fmap` byteStringOfPtr s digestSize
                                 B.withByteArray h $ \hPtr -> bufCopy s hPtr digestSize
                                 loop (s `plusPtr` digestSize) (i+1)
                 | pad /= 0 = do h <- hashBlock i `fmap` byteStringOfPtr s pad
                                 B.withByteArray h $ \hPtr -> bufCopy s hPtr pad
                                 return ()
                 | otherwise = return ()

        digestSize = byteableLength $ hashF B.empty

        byteStringOfPtr :: Ptr Word8 -> Int -> IO ByteString
        byteStringOfPtr ptr digestSz = newForeignPtr_ ptr >>= \fptr -> return $ B.fromForeignPtr fptr 0 digestSz

        hashBlock n b =
            toBytes $ hashF $ B.allocAndFreeze (B.length b+4) $ \ptr -> do
                poke ptr               (f8 (n `shiftR` 24))
                poke (ptr `plusPtr` 1) (f8 (n `shiftR` 16))
                poke (ptr `plusPtr` 2) (f8 (n `shiftR` 8))
                poke (ptr `plusPtr` 3) (f8 n)
                --putWord32BE (fromIntegral n) >> putBytes src)
                withByteArray b $ \srcPtr -> bufCopy (ptr `plusPtr` 4) srcPtr (B.length b)
          where f8 :: Int -> Word8
                f8 = fromIntegral
