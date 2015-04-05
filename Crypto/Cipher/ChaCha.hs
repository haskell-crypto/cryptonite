-- |
-- Module      : Crypto.Cipher.ChaCha
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Cipher.ChaCha
    ( initialize
    , combine
    , generate
    , State
    -- * simple interface for DRG purpose
    , initializeSimple
    , generateSimple
    , StateSimple
    ) where

import Control.Applicative
import Data.SecureMem
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString as B
import Crypto.Internal.ByteArray
import Crypto.Internal.Compat
import Data.Byteable
import Data.Word
import Data.Bits (xor)
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.Storable
import System.IO.Unsafe

-- | ChaCha context
data State = State Int        -- number of rounds
                   SecureMem  -- ChaCha's state
                   ByteString -- previous generated chunk

-- | ChaCha context for DRG purpose (see Crypto.Random.ChaChaDRG)
newtype StateSimple = StateSimple SecureMem -- just ChaCha's state

round64 :: Int -> (Bool, Int)
round64 len
    | len == 0  = (True, 0)
    | m == 0    = (True, len)
    | otherwise = (False, len + (64 - m))
  where m = len `mod` 64

-- | Initialize a new ChaCha context with the number of rounds,
-- the key and the nonce associated.
initialize :: Byteable key
           => Int         -- ^ number of rounds (8,12,20)
           -> key         -- ^ the key (128 or 256 bits)
           -> ByteString  -- ^ the nonce (64 or 96 bits)
           -> State       -- ^ the initial ChaCha state
initialize nbRounds key nonce
    | not (kLen `elem` [16,32])       = error "ChaCha: key length should be 128 or 256 bits"
    | not (nonceLen `elem` [8,12])    = error "ChaCha: nonce length should be 64 or 96 bits"
    | not (nbRounds `elem` [8,12,20]) = error "ChaCha: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- createSecureMem 64 $ \stPtr ->
            withBytePtr nonce $ \noncePtr  ->
            withBytePtr key $ \keyPtr ->
                ccryptonite_chacha_init (castPtr stPtr) kLen keyPtr nonceLen noncePtr
        return $ State nbRounds stPtr B.empty
  where kLen     = byteableLength key
        nonceLen = B.length nonce

-- | Initialize simple ChaCha State
initializeSimple :: ByteArray seed
                 => seed -- ^ a 40 bytes long seed
                 -> StateSimple
initializeSimple seed
    | sLen /= 40 = error "ChaCha Random: seed length should be 40 bytes"
    | otherwise = unsafeDoIO $ do
        stPtr <- createSecureMem 64 $ \stPtr ->
                    withByteArray seed $ \seedPtr ->
                        ccryptonite_chacha_init (castPtr stPtr) 32 seedPtr 8 (seedPtr `plusPtr` 32)
        return $ StateSimple stPtr
  where
    sLen = byteArrayLength seed

-- | Combine the chacha output and an arbitrary message with a xor,
-- and return the combined output and the new state.
combine :: State      -- ^ the current ChaCha state
        -> ByteString -- ^ the source to xor with the generator
        -> (ByteString, State)
combine prev@(State nbRounds prevSt prevOut) src
    | outputLen == 0  = (B.empty, prev)
    | outputLen <= prevBufLen =
        -- we have enough byte in the previous buffer to complete the query
        -- without having to generate any extra bytes
        let (b1,b2) = B.splitAt outputLen prevOut
         in (B.pack $ B.zipWith xor b1 src, State nbRounds prevSt b2)
    | otherwise = unsafePerformIO $ do
        -- adjusted len is the number of bytes lefts to generate after
        -- copying from the previous buffer.
        let adjustedLen = outputLen - prevBufLen
            (roundedAlready, newBytesToGenerate) = round64 adjustedLen
            nextBufLen  = newBytesToGenerate - adjustedLen

        fptr <- B.mallocByteString (newBytesToGenerate + prevBufLen)
        newSt <- withForeignPtr fptr $ \dstPtr ->
            withBytePtr src $ \srcPtr -> do
                -- copy the previous buffer by xor if any
                withBytePtr prevOut $ \prevPtr ->
                    loopXor dstPtr srcPtr prevPtr prevBufLen

                -- then create a new mutable copy of state
                st <- secureMemCopy prevSt
                withSecureMemPtr st $ \stPtr ->
                    ccryptonite_chacha_combine nbRounds
                                               (dstPtr `plusPtr` prevBufLen)
                                               (castPtr stPtr)
                                               (srcPtr `plusPtr` prevBufLen)
                                               (fromIntegral newBytesToGenerate)
                return st
        -- return combined byte
        return ( B.PS fptr 0 outputLen
               , State nbRounds newSt (if roundedAlready then B.empty else B.PS fptr outputLen nextBufLen))
  where
        outputLen  = B.length src
        prevBufLen = B.length prevOut

        loopXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
        loopXor _ _  _  0 = return ()
        loopXor d s1 s2 n = do
            (xor <$> peek s1 <*> peek s2) >>= poke d
            loopXor (d `plusPtr` 1) (s1 `plusPtr` 1) (s2 `plusPtr` 1) (n-1)

-- | Generate a number of bytes from the ChaCha output directly
--
-- TODO: use chacha_generate directly instead of using combine xor'ing with 0.
generate :: State -- ^ the current ChaCha state
         -> Int   -- ^ the length of data to generate
         -> (ByteString, State)
generate st len = combine st (B.replicate len 0)

-- | similar to 'generate' but assume certains values
generateSimple :: ByteArray ba
               => StateSimple
               -> Int
               -> (ba, StateSimple)
generateSimple (StateSimple prevSt) nbBytes = unsafeDoIO $ do
    newSt  <- secureMemCopy prevSt
    output <- byteArrayAlloc nbBytes $ \dstPtr ->
        withSecureMemPtr newSt $ \stPtr ->
            ccryptonite_chacha_random 8 dstPtr (castPtr stPtr) (fromIntegral nbBytes)
    return (output, StateSimple newSt)

foreign import ccall "cryptonite_chacha_init"
    ccryptonite_chacha_init :: Ptr State -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_chacha_combine"
    ccryptonite_chacha_combine :: Int -> Ptr Word8 -> Ptr State -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "cryptonite_chacha_random"
    ccryptonite_chacha_random :: Int -> Ptr Word8 -> Ptr StateSimple -> CUInt -> IO ()

{-
foreign import ccall "cryptonite_chacha_generate"
    ccryptonite_chacha_generate :: Int -> Ptr Word8 -> Ptr State -> CUInt -> IO ()
-}
