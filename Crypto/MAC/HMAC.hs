-- |
-- Module      : Crypto.MAC.HMAC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- provide the HMAC (Hash based Message Authentification Code) base algorithm.
-- <http://en.wikipedia.org/wiki/HMAC>
--
{-# LANGUAGE BangPatterns #-}
module Crypto.MAC.HMAC
    ( hmac
    , HMAC(..)
    -- * incremental
    , Context(..)
    , initialize
    , update
    , updates
    , finalize
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits (xor)
import Data.Byteable
import Crypto.Hash hiding (Context)
import qualified Crypto.Hash as Hash (Context)

-- | Represent an HMAC that is a phantom type with the hash used to produce the mac.
--
-- The Eq instance is constant time.
newtype HMAC a = HMAC { hmacGetDigest :: Digest a }

instance Byteable (HMAC a) where
    toBytes (HMAC b) = toBytes b

instance Eq (HMAC a) where
    (HMAC b1) == (HMAC b2) = constEqBytes (toBytes b1) (toBytes b2)

-- | compute a MAC using the supplied hashing function
hmac :: (Byteable key, HashAlgorithm a)
     => key        -- ^ Secret key
     -> ByteString -- ^ Message to MAC
     -> HMAC a
hmac secret msg = doHMAC hashInit
  where doHMAC :: HashAlgorithm a => Hash.Context a -> HMAC a
        doHMAC !ctxInit = HMAC $ hashF $ B.append opad (toBytes $ hashF $ B.append ipad msg)
          where opad = B.map (xor 0x5c) k'
                ipad = B.map (xor 0x36) k'

                k'  = B.append kt pad
                kt  = if byteableLength secret > fromIntegral blockSize then toBytes (hashF (toBytes secret)) else toBytes secret
                pad = B.replicate (fromIntegral blockSize - B.length kt) 0
                hashF = hashFinalize . hashUpdate ctxInit
                blockSize = hashBlockSize ctxInit

-- | Represent an ongoing HMAC state, that can be appended with 'update'
-- and finalize to an HMAC with 'hmacFinalize'
data Context hashalg = Context !(Hash.Context hashalg) !(Hash.Context hashalg)

-- | Initialize a new incremental HMAC context
initialize :: (Byteable key, HashAlgorithm a)
           => key       -- ^ Secret key
           -> Context a
initialize secret = Context octx ictx
    where ictx = hashUpdates ctxInit [ipad]
          octx = hashUpdates ctxInit [opad]
          ipad = B.map (xor 0x36) k'
          opad = B.map (xor 0x5c) k'

          k'  = B.append kt pad
          kt  = if byteableLength secret > fromIntegral blockSize then toBytes (hashF (toBytes secret)) else toBytes secret
          pad = B.replicate (fromIntegral blockSize - B.length kt) 0
          hashF = hashFinalize . hashUpdate ctxInit
          blockSize = hashBlockSize ctxInit
          !ctxInit = hashInit

-- | Incrementally update a HMAC context
update :: HashAlgorithm a
       => Context a  -- ^ Current HMAC context
       -> ByteString -- ^ Message to append to the MAC
       -> Context a  -- ^ Updated HMAC context
update (Context octx ictx) msg =
    Context octx (hashUpdate ictx msg)

-- | Increamentally update a HMAC context with multiple inputs
updates :: HashAlgorithm a
        => Context a    -- ^ Current HMAC context
        -> [ByteString] -- ^ Messages to append to the MAC
        -> Context a    -- ^ Updated HMAC context
updates (Context octx ictx) msgs =
    Context octx (hashUpdates ictx msgs)

-- | Finalize a HMAC context and return the HMAC.
finalize :: HashAlgorithm a
         => Context a
         -> HMAC a
finalize (Context octx ictx) =
    HMAC $ hashFinalize $ hashUpdates octx [toBytes $ hashFinalize ictx]
