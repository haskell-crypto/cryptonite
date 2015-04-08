-- |
-- Module      : Crypto.Cipher.DES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Cipher.DES
    ( DES
    ) where

import Data.Byteable
import Data.Word
import Crypto.Cipher.Types
import Crypto.Cipher.DES.Primitive
import Crypto.Cipher.DES.Serialization

-- | DES Context
data DES = DES Word64
    deriving (Eq)

instance Cipher DES where
    cipherName    _ = "DES"
    cipherKeySize _ = KeySizeFixed 8
    cipherInit k    = initDES k

{-
instance BlockCipher DES where
    blockSize _ = 8
    ecbEncrypt (DES key) = unblockify . map (encrypt key) . blockify
    ecbDecrypt (DES key) = unblockify . map (decrypt key) . blockify
-}

initDES :: b -> DES
initDES k
    | len == 8  = DES key
    | otherwise = error "DES: not a valid key length (valid=8)"
  where len  = byteableLength k
        (Block key) = toW64 $ toBytes k
