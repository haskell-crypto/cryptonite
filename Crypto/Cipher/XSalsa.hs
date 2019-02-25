-- |
-- Module      : Crypto.Cipher.XSalsa
-- License     : BSD-style
-- Maintainer  : Brandon Hamilton <brandon.hamilton@gmail.com>
-- Stability   : stable
-- Portability : good
--
-- Implementation of XSalsa20 algorithm
-- <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>
-- Based on the Salsa20 algorithm with 256 bit key extended with 192 bit nonce

{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Cipher.XSalsa
    ( initialize
    , combine
    , generate
    , State
    ) where

import           Crypto.Internal.ByteArray (ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports
import           Foreign.Ptr
import           Crypto.Cipher.Salsa hiding (initialize)

-- | Initialize a new XSalsa context with the number of rounds,
-- the key and the nonce associated.
initialize :: (ByteArrayAccess key, ByteArrayAccess nonce)
           => Int    -- ^ number of rounds (8,12,20)
           -> key    -- ^ the key (256 bits)
           -> nonce  -- ^ the nonce (192 bits)
           -> State  -- ^ the initial XSalsa state
initialize nbRounds key nonce
    | kLen /= 32                      = error "XSalsa: key length should be 256 bits"
    | nonceLen /= 24                  = error "XSalsa: nonce length should be 192 bits"
    | not (nbRounds `elem` [8,12,20]) = error "XSalsa: rounds should be 8, 12 or 20"
    | otherwise = unsafeDoIO $ do
        stPtr <- B.alloc 132 $ \stPtr ->
            B.withByteArray nonce $ \noncePtr  ->
            B.withByteArray key   $ \keyPtr ->
                ccryptonite_xsalsa_init stPtr nbRounds kLen keyPtr nonceLen noncePtr
        return $ State stPtr
  where kLen     = B.length key
        nonceLen = B.length nonce

foreign import ccall "cryptonite_xsalsa_init"
    ccryptonite_xsalsa_init :: Ptr State -> Int -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()
