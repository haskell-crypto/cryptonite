-- |
-- Module      : Crypto.PubKey.RSA.PKCS15
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.RSA.PKCS15
    (
    -- * padding and unpadding
      pad
    , padSignature
    , unpad
    -- * private key operations
    , decrypt
    , decryptSafer
    , sign
    , signSafer
    -- * public key operations
    , encrypt
    , verify
    ) where

import Crypto.Random
import Crypto.PubKey.Internal (and')
import Crypto.Types.PubKey.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.PubKey.RSA.Prim
import Crypto.PubKey.RSA.Types
import Crypto.PubKey.RSA (generateBlinder)
import Crypto.PubKey.HashDescr

-- | This produce a standard PKCS1.5 padding for encryption
pad :: CPRG g => g -> Int -> ByteString -> Either Error (ByteString, g)
pad rng len m
    | B.length m > len - 11 = Left MessageTooLong
    | otherwise             =
        let (padding, rng') = getNonNullRandom rng (len - B.length m - 3)
         in Right (B.concat [ B.singleton 0, B.singleton 2, padding, B.singleton 0, m ], rng')

        where {- get random non-null bytes -}
              getNonNullRandom :: CPRG g => g -> Int -> (ByteString, g)
              getNonNullRandom g n =
                    let (bs0,g') = cprgGenerate n g
                        bytes    = B.pack $ filter (/= 0) $ B.unpack $ bs0
                        left     = (n - B.length bytes)
                     in if left == 0
                        then (bytes, g')
                        else let (bend, g'') = getNonNullRandom g' left
                              in (bytes `B.append` bend, g'')

-- | Produce a standard PKCS1.5 padding for signature
padSignature :: Int -> ByteString -> Either Error ByteString
padSignature klen signature
    | klen < siglen+1 = Left SignatureTooLong
    | otherwise       = Right $ B.concat [B.singleton 0,B.singleton 1,padding,B.singleton 0,signature]
    where
        siglen    = B.length signature
        padding   = B.replicate (klen - siglen - 3) 0xff

-- | Try to remove a standard PKCS1.5 encryption padding.
unpad :: ByteString -> Either Error ByteString
unpad packed
    | paddingSuccess = Right m
    | otherwise      = Left MessageNotRecognized
    where
        (zt, ps0m)   = B.splitAt 2 packed
        (ps, zm)     = B.span (/= 0) ps0m
        (z, m)       = B.splitAt 1 zm
        paddingSuccess = and' [ zt == "\x00\x02"
                              , z  == "\x00"
                              , B.length ps >= 8
                              ]

-- | decrypt message using the private key.
--
-- When the decryption is not in a context where an attacker could gain
-- information from the timing of the operation, the blinder can be set to None.
--
-- If unsure always set a blinder or use decryptSafer
decrypt :: Maybe Blinder -- ^ optional blinder
        -> PrivateKey    -- ^ RSA private key
        -> ByteString    -- ^ cipher text
        -> Either Error ByteString
decrypt blinder pk c
    | B.length c /= (private_size pk) = Left MessageSizeIncorrect
    | otherwise                       = unpad $ dp blinder pk c

-- | decrypt message using the private key and by automatically generating a blinder.
decryptSafer :: CPRG g
             => g          -- ^ random generator
             -> PrivateKey -- ^ RSA private key
             -> ByteString -- ^ cipher text
             -> (Either Error ByteString, g)
decryptSafer rng pk b =
    let (blinder, rng') = generateBlinder rng (private_n pk)
     in (decrypt (Just blinder) pk b, rng')

-- | encrypt a bytestring using the public key and a CPRG random generator.
--
-- the message need to be smaller than the key size - 11
encrypt :: CPRG g => g -> PublicKey -> ByteString -> (Either Error ByteString, g)
encrypt rng pk m = do
    case pad rng (public_size pk) m of
        Left err         -> (Left err, rng)
        Right (em, rng') -> (Right (ep pk em), rng')

-- | sign message using private key, a hash and its ASN1 description
--
-- When the signature is not in a context where an attacker could gain
-- information from the timing of the operation, the blinder can be set to None.
--
-- If unsure always set a blinder or use signSafer
sign :: Maybe Blinder -- ^ optional blinder
     -> HashDescr     -- ^ hash descriptor
     -> PrivateKey    -- ^ private key
     -> ByteString    -- ^ message to sign
     -> Either Error ByteString
sign blinder hashDescr pk m = dp blinder pk `fmap` makeSignature hashDescr (private_size pk) m

-- | sign message using the private key and by automatically generating a blinder.
signSafer :: CPRG g
          => g          -- ^ random generator
          -> HashDescr  -- ^ Hash descriptor
          -> PrivateKey -- ^ private key
          -> ByteString -- ^ message to sign
          -> (Either Error ByteString, g)
signSafer rng hashDescr pk m =
    let (blinder, rng') = generateBlinder rng (private_n pk)
     in (sign (Just blinder) hashDescr pk m, rng')

-- | verify message with the signed message
verify :: HashDescr -> PublicKey -> ByteString -> ByteString -> Bool
verify hashDescr pk m sm =
    case makeSignature hashDescr (public_size pk) m of
        Left _  -> False
        Right s -> s == (ep pk sm)

{- makeSignature for sign and verify -}
makeSignature :: HashDescr -> Int -> ByteString -> Either Error ByteString
makeSignature hashDescr klen m = padSignature klen signature
    where signature = (digestToASN1 hashDescr) $ (hashFunction hashDescr) m
