-- |
-- Module      : Crypto.Cipher.Types.GF
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- Slow Galois Field arithmetic for generic XTS and GCM implementation
--
module Crypto.Cipher.Types.GF
    (
    -- * XTS support
      xtsGFMul
    ) where

import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.Byteable
import Foreign.Storable
import Foreign.Ptr
import Data.Word
import Data.Bits

-- block size need to be 128 bits.
--
-- FIXME: add support for big endian.
xtsGFMul :: ByteString -> ByteString
xtsGFMul b
    | B.length b == 16 = B.unsafeCreate (B.length b) $ \dst ->
                         withBytePtr b $ \src -> do
                         (hi,lo) <- gf <$> peek (castPtr src) <*> peek (castPtr src `plusPtr` 8)
                         poke (castPtr dst) lo
                         poke (castPtr dst `plusPtr` 8) hi
    | otherwise        = error "unsupported block size in GF"
  where gf :: Word64 -> Word64 -> (Word64, Word64)
        gf srcLo srcHi =
            ((if carryLo then (.|. 1) else id) (srcHi `shiftL` 1)
            ,(if carryHi then xor 0x87 else id) $ (srcLo `shiftL` 1)
            )
          where carryHi = srcHi `testBit` 63 
                carryLo = srcLo `testBit` 63
{-
	const uint64_t gf_mask = cpu_to_le64(0x8000000000000000ULL);
	uint64_t r = ((a->q[1] & gf_mask) ? cpu_to_le64(0x87) : 0);
	a->q[1] = cpu_to_le64((le64_to_cpu(a->q[1]) << 1) | (a->q[0] & gf_mask ? 1 : 0));
	a->q[0] = cpu_to_le64(le64_to_cpu(a->q[0]) << 1) ^ r;
-}
