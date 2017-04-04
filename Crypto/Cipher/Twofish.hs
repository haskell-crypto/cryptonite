module Crypto.Cipher.Twofish
    ( Twofish128
    ) where

import Crypto.Cipher.Twofish.Primitive
import Crypto.Cipher.Types

newtype Twofish128 = Twofish128 Twofish

instance Cipher Twofish128 where
    cipherName    _ = "Twofish128"
    cipherKeySize _ = KeySizeFixed 16
    cipherInit key    = Twofish128 `fmap` initTwofish key

instance BlockCipher Twofish128 where
    blockSize     _ = 16
    ecbEncrypt (Twofish128 key) = encrypt key
    ecbDecrypt (Twofish128 key) = decrypt key