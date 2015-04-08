-- |
-- Module      : Crypto.Cipher.DES.Serialization
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- basic routine to convert between W64 and bytestring for DES.
--
{-# LANGUAGE CPP #-}
module Crypto.Cipher.DES.Serialization
    ( toW64
    , toBS
    , blockify
    , unblockify
    ) where

import qualified Data.ByteString as B
import Crypto.Cipher.DES.Primitive (Block(..))

#ifdef ARCH_IS_LITTLE_ENDIAN
import Data.Word (Word64)
import Data.Byteable (withBytePtr)
import qualified Data.ByteString.Internal as B (inlinePerformIO, unsafeCreate)
import Foreign.Storable
import Foreign.Ptr (castPtr, plusPtr, Ptr)
import Data.Bits (shiftL, shiftR, (.|.), (.&.))
#else
import Data.Bits (shiftL, shiftR, (.|.))
#endif

#ifdef ARCH_IS_LITTLE_ENDIAN
-- | convert a 8 byte bytestring big endian to a host one
toW64 :: B.ByteString -> Block
toW64 b = Block $ B.inlinePerformIO $ withBytePtr b $ \ptr -> (be64 `fmap` peek (castPtr ptr))

-- | convert a word64 to a bytestring in big endian format
toBS :: Block -> B.ByteString
toBS (Block w) = B.unsafeCreate 8 $ \ptr -> poke (castPtr ptr) (be64 w)

-- | Create a strict bytestring out of DES blocks
unblockify :: [Block] -> B.ByteString
unblockify blocks = B.unsafeCreate (nbBlocks * 8) $ \initPtr -> pokeTo (castPtr initPtr) blocks
  where nbBlocks = length blocks
        pokeTo :: Ptr Word64 -> [Block] -> IO ()
        pokeTo _   []           = return ()
        pokeTo ptr (Block x:xs) = poke ptr (be64 x) >> pokeTo (ptr `plusPtr` 8) xs

be64 :: Word64 -> Word64
be64 w =
        (w `shiftR` 56)                  .|. (w `shiftL` 56)
    .|. ((w `shiftR` 40) .&. 0xff00)     .|. ((w .&. 0xff00) `shiftL` 40)
    .|. ((w `shiftR` 24) .&. 0xff0000)   .|. ((w .&. 0xff0000) `shiftL` 24)
    .|. ((w `shiftR` 8)  .&. 0xff000000) .|. ((w .&. 0xff000000) `shiftL` 8)
#else
-- | convert a 8 byte bytestring to a little endian word64
toW64 :: B.ByteString -> Block
toW64 bs = Block $ case B.unpack bs of
            [a,b,c,d,e,f,g,h] -> shl h 0  .|. shl g 8 .|. shl f 16 .|. shl e 24 .|.
                                 shl d 32 .|. shl c 40 .|. shl b 48 .|. shl a 56
            _                 -> 0
  where shl w n = fromIntegral w `shiftL` n

-- | convert a word64 to a bytestring in little endian format
toBS :: Block -> B.ByteString
toBS (Block b) = B.pack $ map (shr b) [56,48,40,32,24,16,8,0]
  where shr w n = fromIntegral (w `shiftR` n)

-- | Create a strict bytestring out of DES blocks
unblockify :: [Block] -> B.ByteString
unblockify = B.concat . map toBS
#endif

-- | create DES blocks from a strict bytestring
blockify :: B.ByteString -> [Block]
blockify s | B.null s  = []
           | otherwise = let (s1,s2) = B.splitAt 8 s
                          in toW64 s1:blockify s2
