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
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
import           Crypto.Hash hiding (Context)
import qualified Crypto.Hash as Hash (Context)
import           Crypto.Hash.IO
import           Crypto.Internal.ByteArray (SecureBytes, Bytes, ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B
import           Crypto.Internal.Bytes
import           Crypto.Internal.Compat
import           Crypto.Internal.Imports

-- | Represent an HMAC that is a phantom type with the hash used to produce the mac.
--
-- The Eq instance is constant time.
newtype HMAC a = HMAC { hmacGetDigest :: Digest a }
    deriving (ByteArrayAccess)

instance Eq (HMAC a) where
    (HMAC b1) == (HMAC b2) = B.constEq b1 b2

-- | compute a MAC using the supplied hashing function
hmac :: (ByteArrayAccess key, ByteArray message, HashAlgorithm a)
     => key     -- ^ Secret key
     -> message -- ^ Message to MAC
     -> HMAC a
hmac secret msg = finalize $ updates (initialize secret) [msg]

-- | Represent an ongoing HMAC state, that can be appended with 'update'
-- and finalize to an HMAC with 'hmacFinalize'
data Context hashalg = Context !(Hash.Context hashalg) !(Hash.Context hashalg)

-- | Initialize a new incremental HMAC context
initialize :: (ByteArrayAccess key, HashAlgorithm a)
           => key       -- ^ Secret key
           -> Context a
initialize secret = unsafeDoIO (doHashAlg undefined)
  where
        doHashAlg :: HashAlgorithm a => a -> IO (Context a)
        doHashAlg alg = do
            !withKey <- case B.length secret `compare` blockSize of
                            EQ -> return $ B.withByteArray secret
                            LT -> do key <- B.alloc blockSize $ \k -> do
                                        bufSet k 0 blockSize
                                        B.withByteArray secret $ \s -> bufCopy k s (B.length secret)
                                     return $ B.withByteArray (key :: SecureBytes)
                            GT -> do
                                -- hash the secret key
                                ctx <- hashMutableInitWith alg
                                hashMutableUpdate ctx secret
                                digest <- hashMutableFinalize ctx
                                hashMutableScrub ctx
                                -- pad it if necessary
                                if digestSize < blockSize
                                    then do
                                        key <- B.alloc blockSize $ \k -> do
                                            bufSet k 0 blockSize
                                            B.withByteArray digest $ \s -> bufCopy k s (B.length digest)
                                        return $ B.withByteArray (key :: SecureBytes)
                                    else
                                       return $ B.withByteArray digest
            (inner, outer) <- withKey $ \keyPtr ->
                (,) <$> B.alloc blockSize (\p -> bufXorWith p 0x36 keyPtr blockSize)
                    <*> B.alloc blockSize (\p -> bufXorWith p 0x5c keyPtr blockSize)
            return $ Context (hashUpdates initCtx [outer :: ByteString])
                             (hashUpdates initCtx [inner :: ByteString])
          where 
                blockSize  = hashBlockSize alg
                digestSize = hashDigestSize alg
                initCtx    = hashInitWith alg
{-# NOINLINE initialize #-}

-- | Incrementally update a HMAC context
update :: (ByteArrayAccess message, HashAlgorithm a)
       => Context a  -- ^ Current HMAC context
       -> message    -- ^ Message to append to the MAC
       -> Context a  -- ^ Updated HMAC context
update (Context octx ictx) msg =
    Context octx (hashUpdate ictx msg)

-- | Increamentally update a HMAC context with multiple inputs
updates :: (ByteArrayAccess message, HashAlgorithm a)
        => Context a -- ^ Current HMAC context
        -> [message] -- ^ Messages to append to the MAC
        -> Context a -- ^ Updated HMAC context
updates (Context octx ictx) msgs =
    Context octx (hashUpdates ictx msgs)

-- | Finalize a HMAC context and return the HMAC.
finalize :: HashAlgorithm a
         => Context a
         -> HMAC a
finalize (Context octx ictx) =
    HMAC $ hashFinalize $ hashUpdates octx [hashFinalize ictx]
