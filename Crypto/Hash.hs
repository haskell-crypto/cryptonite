{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.Hash
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Generalized cryptographic hash interface, that you can use with cryptographic hash
-- algorithm that belong to the HashAlgorithm type class.
--
-- > import Crypto.Hash
-- >
-- > sha1 :: ByteString -> Digest SHA1
-- > sha1 = hash
-- >
-- > hexSha3_512 :: ByteString -> String
-- > hexSha3_512 bs = show (hash bs :: Digest SHA3_512)
--
module Crypto.Hash
    (
    -- * Types
      HashAlgorithm(..)
    , HashFunctionBS
    , HashFunctionLBS
    , Context
    , Digest
    -- * Functions
    , digestToByteString
    , digestToHexByteString
    , hash
    , hashlazy
    , hashUpdate
    , hashInitAlg
    -- * hash algorithms
    , MD2(..)
    , MD4(..)
    , MD5(..)
    , SHA1(..)
    , SHA224(..)
    , SHA256(..)
    , SHA384(..)
    , SHA512(..)
    , RIPEMD160(..)
    , Tiger(..)
    , SHA3_224(..)
    , SHA3_256(..)
    , SHA3_384(..)
    , SHA3_512(..)
    , Skein256_224(..)
    , Skein256_256(..)
    , Skein512_224(..)
    , Skein512_256(..)
    , Skein512_384(..)
    , Skein512_512(..)
    , Whirlpool(..)
    ) where

import Crypto.Hash.Types
import Crypto.Hash.Utils
import Data.ByteString (ByteString)
import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA3 as SHA3
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512
import qualified Crypto.Hash.Whirlpool as Whirlpool

-- | Alias to a single pass hash function that operate on a strict bytestring
type HashFunctionBS a = ByteString -> Digest a

-- | Alias to a single pass hash function that operate on a lazy bytestring
type HashFunctionLBS a = L.ByteString -> Digest a

-- | run hashUpdates on one single bytestring and return the updated context.
hashUpdate :: HashAlgorithm a => Context a -> ByteString -> Context a
hashUpdate ctx b = hashUpdates ctx [b]

-- | Hash a strict bytestring into a digest.
hash :: HashAlgorithm a => ByteString -> Digest a
hash bs = hashFinalize $ hashUpdate hashInit bs

-- | Hash a lazy bytestring into a digest.
hashlazy :: HashAlgorithm a => L.ByteString -> Digest a
hashlazy lbs = hashFinalize $ hashUpdates hashInit (L.toChunks lbs)

-- | Return the hexadecimal (base16) bytestring of the digest
digestToHexByteString :: Digest a -> ByteString
digestToHexByteString = toHex . toBytes

#define DEFINE_INSTANCE(NAME, MODULENAME, BLOCKSIZE) \
data NAME = NAME deriving Show; \
instance HashAlgorithm NAME where \
    { hashInit = Context c where { (MODULENAME.Ctx c) = MODULENAME.init } \
    ; hashBlockSize ~(Context _) = BLOCKSIZE \
    ; hashUpdates (Context c) bs = Context nc where { (MODULENAME.Ctx nc) = MODULENAME.updates (MODULENAME.Ctx c) bs } \
    ; hashFinalize (Context c) = Digest $ MODULENAME.finalize (MODULENAME.Ctx c) \
    ; digestFromByteString bs = if B.length bs == len then (Just $ Digest bs) else Nothing where { len = B.length (MODULENAME.finalize MODULENAME.init) } \
    };

#define DEFINE_INSTANCE_LEN(NAME, MODULENAME, LEN, BLOCKSIZE) \
data NAME = NAME deriving Show; \
instance HashAlgorithm NAME where \
    { hashInit = Context c where { (MODULENAME.Ctx c) = MODULENAME.init LEN } \
    ; hashBlockSize ~(Context _) = BLOCKSIZE \
    ; hashUpdates (Context c) bs = Context nc where { (MODULENAME.Ctx nc) = MODULENAME.updates (MODULENAME.Ctx c) bs } \
    ; hashFinalize (Context c) = Digest $ MODULENAME.finalize (MODULENAME.Ctx c) \
    ; digestFromByteString bs = if B.length bs == len then (Just $ Digest bs) else Nothing where { len = B.length (MODULENAME.finalize (MODULENAME.init LEN)) } \
    };

-- | MD2 cryptographic hash
DEFINE_INSTANCE(MD2, MD2, 16)
-- | MD4 cryptographic hash
DEFINE_INSTANCE(MD4, MD4, 64)
-- | MD5 cryptographic hash
DEFINE_INSTANCE(MD5, MD5, 64)
-- | SHA1 cryptographic hash
DEFINE_INSTANCE(SHA1, SHA1, 64)
-- | SHA224 cryptographic hash
DEFINE_INSTANCE(SHA224, SHA224, 64)
-- | SHA256 cryptographic hash
DEFINE_INSTANCE(SHA256, SHA256, 64)
-- | SHA384 cryptographic hash
DEFINE_INSTANCE(SHA384, SHA384, 128)
-- | SHA512 cryptographic hash
DEFINE_INSTANCE(SHA512, SHA512, 128)

-- | RIPEMD160 cryptographic hash
DEFINE_INSTANCE(RIPEMD160, RIPEMD160, 64)
-- | Whirlpool cryptographic hash
DEFINE_INSTANCE(Whirlpool, Whirlpool, 64)
-- | Tiger cryptographic hash
DEFINE_INSTANCE(Tiger, Tiger, 64)

-- | SHA3 (224 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(SHA3_224, SHA3, 224, 144)
-- | SHA3 (256 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(SHA3_256, SHA3, 256, 136)
-- | SHA3 (384 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(SHA3_384, SHA3, 384, 104)
-- | SHA3 (512 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(SHA3_512, SHA3, 512, 72)

-- | Skein256 (224 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein256_224, Skein256, 224, 32)
-- | Skein256 (256 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein256_256, Skein256, 256, 32)

-- | Skein512 (224 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein512_224, Skein512, 224, 64)
-- | Skein512 (256 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein512_256, Skein512, 256, 64)
-- | Skein512 (384 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein512_384, Skein512, 384, 64)
-- | Skein512 (512 bits version) cryptographic hash
DEFINE_INSTANCE_LEN(Skein512_512, Skein512, 512, 64)

-- | Initialize a new context for a specified hash algorithm
hashInitAlg :: HashAlgorithm alg => alg -> Context alg
hashInitAlg _ = hashInit
