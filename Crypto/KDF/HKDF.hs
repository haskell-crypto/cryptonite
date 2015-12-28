-- |
-- Module      : Crypto.KDF.HKDF
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Key Derivation Function based on HMAC
--
-- See rfc5869
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.KDF.HKDF
    ( PRK
    , extract
    , extractSkip
    , expand
    ) where

import           Data.Word
import           Crypto.Hash 
import           Crypto.MAC.HMAC
import           Crypto.Internal.ByteArray (ScrubbedBytes, Bytes, ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B

-- | Pseudo Random Key
data PRK a = PRK (HMAC a) | PRK_NoExpand ScrubbedBytes
    deriving (Eq)

-- | Extract a Pseudo Random Key using the parameter and the underlaying hash mechanism
extract :: (HashAlgorithm a, ByteArrayAccess salt, ByteArrayAccess ikm)
        => salt  -- ^ Salt
        -> ikm   -- ^ Input Keying Material
        -> PRK a -- ^ Pseudo random key
extract salt ikm = PRK $ hmac salt ikm

-- | Create a PRK directly from the input key material, skipping any hmacing
extractSkip :: (HashAlgorithm a, ByteArrayAccess ikm)
            => ikm
            -> PRK a
extractSkip ikm = PRK_NoExpand $ B.convert ikm

-- | Expand key material of specific length out of the parameters
expand :: (HashAlgorithm a, ByteArrayAccess info, ByteArray out)
       => PRK a      -- ^ Pseudo Random Key
       -> info       -- ^ Optional context and application specific information
       -> Int        -- ^ Output length in bytes
       -> out        -- ^ Output data
expand prkAt infoAt outputLength =
    let hF = hFGet prkAt
     in B.concat $ loop hF B.empty outputLength 1
  where
    hFGet :: (HashAlgorithm a, ByteArrayAccess b) => PRK a -> (b -> HMAC a)
    hFGet prk = case prk of
             PRK hmacKey      -> hmac hmacKey
             PRK_NoExpand ikm -> hmac ikm

    info :: ScrubbedBytes
    info = B.convert infoAt

    loop :: HashAlgorithm a
         => (ScrubbedBytes -> HMAC a)
         -> ScrubbedBytes
         -> Int
         -> Word8
         -> [ScrubbedBytes]
    loop hF tim1 n i
        | n <= 0    = []
        | otherwise =
            let input   = B.concat [tim1,info,B.singleton i] :: ScrubbedBytes
                ti      = B.convert $ hF input
                hashLen = B.length ti
                r       = n - hashLen
             in (if n >= hashLen then ti else B.take n ti)
              : loop hF ti r (i+1)

