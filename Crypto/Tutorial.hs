{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# LANGUAGE OverloadedStrings #-}

{-| How to use @cryptonite@

> -- | Beware MUST BE 256bits as we use AES256
> import Data.ByteString (ByteString)
> import Crypto.Cipher.AES (AES256)
> import Crypto.Cipher.Types (BlockCipher(..), Cipher(..),nullIV)
> import Crypto.Error (CryptoFailable(..))
>
> secretKey :: ByteString
> secretKey = "012-456-89A-CDE-012-456-89A-CDE-"
>
> encrypt :: ByteString -> ByteString -> ByteString
> encrypt secret = ctrCombine ctx nullIV
>   where
>     ctx = cipherInitNoErr (cipherMakeKey (undefined :: AES256) secret)
>     cipherInitNoErr :: BlockCipher c => Key c -> c
>     cipherInitNoErr (Key k) = case cipherInit k of
>       CryptoPassed a -> a
>       CryptoFailed e -> error (show e)
>     cipherMakeKey :: Cipher cipher => cipher -> ByteString -> Key cipher
>     cipherMakeKey _ = Key -- Yeah Lazyness!!!!!!
>
>
> decrypt :: ByteString -> ByteString -> ByteString
> decrypt = encrypt

|-}

module Crypto.Tutorial () where

import Crypto.Cipher.Types
