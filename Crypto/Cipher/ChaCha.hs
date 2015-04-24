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

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray, SecureBytes, withByteArray)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Data.Bits (xor)
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Foreign.C.Types
import           Foreign.Storable

-- | ChaCha context
data State = State Int         -- number of rounds
                   SecureBytes -- ChaCha's state
                   ByteString  -- previous generated chunk

-- | ChaCha context for DRG purpose (see Crypto.Random.ChaChaDRG)
newtype StateSimple = StateSimple SecureBytes -- just ChaCha's state

round64 :: Int -> (Bool, Int)
round64 len
    | len == 0  = (True, 0)
    | m == 0    = (True, len)
    | otherwise = (False, len + (64 - m))
  where m = len `mod` 64

-- | Initialize a new ChaCha context with the number of rounds,
-- the key and the nonce associated.
initialize :: ByteArrayAccess key
           => Int         -- ^ number of rounds (8,12,20)
           -> key         -- ^ the key (128 or 256 bits)
           -> ByteString  -- ^ the nonce (64 or 96 bits)
           -> State       -- ^ the initial ChaCha state
initialize nbRounds key nonce
    | not (kLen `elem` [16,32])       = error "ChaCha: key length should be 128 or 256 bits"
    | not (nonceLen `elem` [8,12])    = error "ChaCha: nonce length should be 64 or 96 bits"
    | not (nbRounds `elem` [8,12,20]) = error "ChaCha: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 64 $ \stPtr ->
            withByteArray nonce $ \noncePtr  ->
            withByteArray key $ \keyPtr ->
                ccryptonite_chacha_init (castPtr stPtr) kLen keyPtr nonceLen noncePtr
        return $ State nbRounds stPtr B.empty
  where kLen     = B.length key
        nonceLen = B.length nonce

-- | Initialize simple ChaCha State
initializeSimple :: ByteArray seed
                 => seed -- ^ a 40 bytes long seed
                 -> StateSimple
initializeSimple seed
    | sLen /= 40 = error "ChaCha Random: seed length should be 40 bytes"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 64 $ \stPtr ->
                    withByteArray seed $ \seedPtr ->
                        ccryptonite_chacha_init (castPtr stPtr) 32 seedPtr 8 (seedPtr `plusPtr` 32)
        return $ StateSimple stPtr
  where
    sLen = B.length seed

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
        let (b1,b2) = BS.splitAt outputLen prevOut
         in (B.xor b1 src, State nbRounds prevSt b2)
    | otherwise = unsafeDoIO $ do
        -- adjusted len is the number of bytes lefts to generate after
        -- copying from the previous buffer.
        let adjustedLen = outputLen - prevBufLen
            (roundedAlready, newBytesToGenerate) = round64 adjustedLen
            nextBufLen  = newBytesToGenerate - adjustedLen

        fptr <- BS.mallocByteString (newBytesToGenerate + prevBufLen)
        newSt <- withForeignPtr fptr $ \dstPtr ->
            withByteArray src $ \srcPtr -> do
                -- copy the previous buffer by xor if any
                withByteArray prevOut $ \prevPtr ->
                    loopXor dstPtr srcPtr prevPtr prevBufLen

                -- then create a new mutable copy of state
                B.copy prevSt $ \stPtr ->
                    ccryptonite_chacha_combine nbRounds
                                               (dstPtr `plusPtr` prevBufLen)
                                               (castPtr stPtr)
                                               (srcPtr `plusPtr` prevBufLen)
                                               (fromIntegral newBytesToGenerate)

        -- return combined byte
        return ( BS.PS fptr 0 outputLen
               , State nbRounds newSt (if roundedAlready then BS.empty else BS.PS fptr outputLen nextBufLen))
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
generate st len = combine st (BS.replicate len 0)

-- | similar to 'generate' but assume certains values
generateSimple :: ByteArray ba
               => StateSimple
               -> Int
               -> (ba, StateSimple)
generateSimple (StateSimple prevSt) nbBytes = unsafeDoIO $ do
    newSt  <- B.copy prevSt (\_ -> return ())
    output <- B.alloc nbBytes $ \dstPtr ->
        withByteArray newSt $ \stPtr ->
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
