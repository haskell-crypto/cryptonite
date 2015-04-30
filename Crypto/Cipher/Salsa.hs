-- |
-- Module      : Crypto.Cipher.Salsa
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Cipher.Salsa
    ( initialize
    , combine
    , generate
    , State
    ) where

import Data.ByteString (ByteString)
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray, SecureBytes)
import qualified Crypto.Internal.ByteArray as B
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString as BS
import Crypto.Internal.Compat
import Crypto.Internal.Imports
import Data.Bits (xor)
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.Storable

-- | Salsa context
data State = State Int         -- number of rounds
                   SecureBytes -- Salsa's state
                   ByteString  -- previous generated chunk

round64 :: Int -> (Bool, Int)
round64 len
    | len == 0  = (True, 0)
    | m == 0    = (True, len)
    | otherwise = (False, len + (64 - m))
  where m = len `mod` 64

-- | Initialize a new Salsa context with the number of rounds,
-- the key and the nonce associated.
initialize :: (ByteArrayAccess key, ByteArray nonce)
           => Int    -- ^ number of rounds (8,12,20)
           -> key    -- ^ the key (128 or 256 bits)
           -> nonce  -- ^ the nonce (64 or 96 bits)
           -> State  -- ^ the initial Salsa state
initialize nbRounds key nonce
    | not (kLen `elem` [16,32])       = error "Salsa: key length should be 128 or 256 bits"
    | not (nonceLen `elem` [8,12])    = error "Salsa: nonce length should be 64 or 96 bits"
    | not (nbRounds `elem` [8,12,20]) = error "Salsa: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 64 $ \stPtr ->
            B.withByteArray nonce $ \noncePtr  ->
            B.withByteArray key   $ \keyPtr ->
                ccryptonite_salsa_init stPtr kLen keyPtr nonceLen noncePtr
        return $ State nbRounds stPtr B.empty
  where kLen     = B.length key
        nonceLen = B.length nonce

-- | Combine the salsa output and an arbitrary message with a xor,
-- and return the combined output and the new state.
combine :: ByteArray ba
        => State      -- ^ the current Salsa state
        -> ba         -- ^ the source to xor with the generator
        -> (ba, State)
combine prev@(State nbRounds prevSt prevOut) src
    | outputLen == 0  = (B.empty, prev)
    | outputLen <= prevBufLen =
        -- we have enough byte in the previous buffer to complete the query
        -- without having to generate any extra bytes
        let (b1,b2) = BS.splitAt outputLen prevOut
         in (B.convert $ BS.pack $ BS.zipWith xor b1 (B.convert src), State nbRounds prevSt b2)
    | otherwise = unsafeDoIO $ do
        -- adjusted len is the number of bytes lefts to generate after
        -- copying from the previous buffer.
        let adjustedLen = outputLen - prevBufLen
            (roundedAlready, newBytesToGenerate) = round64 adjustedLen
            nextBufLen  = newBytesToGenerate - adjustedLen

        fptr <- BS.mallocByteString (newBytesToGenerate + prevBufLen)
        newSt <- withForeignPtr fptr $ \dstPtr ->
            B.withByteArray src $ \srcPtr -> do
                -- copy the previous buffer by xor if any
                B.withByteArray prevOut $ \prevPtr ->
                    loopXor dstPtr srcPtr prevPtr prevBufLen

                -- then create a new mutable copy of state
                B.copy prevSt $ \stPtr ->
                    ccryptonite_salsa_combine nbRounds
                                               (dstPtr `plusPtr` prevBufLen)
                                               (castPtr stPtr)
                                               (srcPtr `plusPtr` prevBufLen)
                                               (fromIntegral newBytesToGenerate)
        -- return combined byte
        return ( B.convert (BS.PS fptr 0 outputLen)
               , State nbRounds newSt (if roundedAlready then BS.empty else BS.PS fptr outputLen nextBufLen))
  where
        outputLen  = B.length src
        prevBufLen = B.length prevOut

        loopXor :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
        loopXor _ _  _  0 = return ()
        loopXor d s1 s2 n = do
            (xor <$> peek s1 <*> peek s2) >>= poke d
            loopXor (d `plusPtr` 1) (s1 `plusPtr` 1) (s2 `plusPtr` 1) (n-1)

-- | Generate a number of bytes from the Salsa output directly
--
-- TODO: use salsa_generate directly instead of using combine xor'ing with 0.
generate :: ByteArray ba
         => State -- ^ the current Salsa state
         -> Int   -- ^ the length of data to generate
         -> (ba, State)
generate st len = combine st (B.zero len)

foreign import ccall "cryptonite_salsa_init"
    ccryptonite_salsa_init :: Ptr State -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall "cryptonite_salsa_combine"
    ccryptonite_salsa_combine :: Int -> Ptr Word8 -> Ptr State -> Ptr Word8 -> CUInt -> IO ()

{-
foreign import ccall "cryptonite_salsa_generate"
    ccryptonite_salsa_generate :: Int -> Ptr Word8 -> Ptr State -> CUInt -> IO ()
-}
