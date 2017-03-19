
{- How to use @cryptonite@ with symmetric block ciphers

> {-# LANGUAGE OverloadedStrings #-}
> {-# LANGUAGE ScopedTypeVariables #-}
> {-# LANGUAGE GADTs #-}
> 
> import           Crypto.Cipher.AES (AES256)
> import           Crypto.Cipher.Types (BlockCipher(..), Cipher(..), nullIV, KeySizeSpecifier(..))
> import           Crypto.Error (CryptoFailable(..), CryptoError(..))
> 
> import qualified Crypto.Random.Types as CRT
> 
> import           Data.ByteArray (ByteArray)
> import           Data.ByteString (ByteString)
> 
> -- | Not required, but most general implementation
> data Key c a where
>   Key :: (BlockCipher c, ByteArray a) => a -> Key c a 
> 
> genPrivateKey :: forall m c a. (CRT.MonadRandom m, BlockCipher c, ByteArray a) 
>               => c -> m (Key c a) 
> genPrivateKey _ = fmap Key $ CRT.getRandomBytes $
>   case cipherKeySize (undefined :: c) of
>     KeySizeRange _ maxSize -> maxSize 
>     KeySizeFixed ks -> ks 
>     KeySizeEnum [] -> error "No key size specified"
>     KeySizeEnum kss -> last kss -- largest key size
>     
> initCipher :: (BlockCipher c, ByteArray a) => Key c a -> Either CryptoError c
> initCipher (Key k) = case cipherInit k of
>   CryptoFailed e -> Left e
>   CryptoPassed a -> Right a
> 
> encrypt :: (BlockCipher c, ByteArray a) => Key c a -> a -> Either CryptoError a
> encrypt privKey msg = 
>   case initCipher privKey of
>     Left e -> Left e
>     Right c -> Right $ ctrCombine c nullIV msg
>     
> decrypt :: (BlockCipher c, ByteArray a) => Key c a -> a -> Either CryptoError a 
> decrypt = encrypt
> 
> exampleAES256 :: ByteString -> IO ()
> exampleAES256 msg = do
>   privKey <- genPrivateKey (undefined :: AES256)
>   let eMsg = encrypt privKey msg >>= decrypt privKey
>   case eMsg of
>     Left err -> error $ show err
>     Right msg' -> do
>       putStrLn $ "Original Message: " ++ show msg
>       putStrLn $ "Message after encryption & decryption: " ++ show msg'
>
> -- | More Examples... ?

|-}

module Crypto.Tutorial.General where
