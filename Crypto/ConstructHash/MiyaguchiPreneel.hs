-- |
-- Module      : Crypto.ConstructHash.MiyaguchiPreneel
-- License     : BSD-style
-- Maintainer  : Kei Hibino <ex8k.hibino@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- provide the hash function construction method from block cipher
-- <https://en.wikipedia.org/wiki/One-way_compression_function>
--
module Crypto.ConstructHash.MiyaguchiPreneel ( mp, cipherInit' ) where

import           Data.List (foldl')

import           Crypto.Cipher.Types
import           Crypto.Error (eitherCryptoError)
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray, Bytes)
import qualified Crypto.Internal.ByteArray as B


-- | Compute Miyaguchi-Preneel one way compress using the supplied block cipher.
--   Simple usage /mp (cipherInit' :: ByteString -> AES128) msg/
mp :: (ByteArrayAccess bin, ByteArray bout, ByteArray ba, BlockCipher cipher)
   => (ba -> cipher) -- ^ key build function to compute Miyaguchi-Preneel
   -> bin            -- ^ input message
   -> bout           -- ^ output tag
mp g = B.convert . foldl' (step $ g . B.convert) (B.replicate bsz 0) . chunks . B.convert
  where
    bsz = blockSize ( g B.empty {- dummy to get block size -} )
    chunks msg
      | B.null tl  =  [hd :: Bytes]
      | otherwise  =   hd : chunks tl
      where
        (hd, tl) = B.splitAt bsz msg

-- | Simple key build function, which may raise size error.
cipherInit' :: (ByteArray ba, Cipher k) => ba -> k
cipherInit' = either (error . show) id . eitherCryptoError . cipherInit

-- | computation step of Miyaguchi-Preneel
step :: (ByteArray ba, BlockCipher k)
     => (ba -> k)
     -> ba
     -> ba
     -> ba
step g iv msg =
    ecbEncrypt k pmsg `bxor` iv `bxor` pmsg
  where
    k = g iv
    pmsg = pad0 k msg

pad0 :: (ByteArray ba, BlockCipher k) => k -> ba -> ba
pad0 k s = s `B.append` B.replicate (blockSize k - B.length s) 0

bxor :: ByteArray ba => ba -> ba -> ba
bxor = B.xor
