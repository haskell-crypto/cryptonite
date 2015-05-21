-- |
-- Module      : Crypto.PubKey.HashDescr
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Standard digests wrapped in ASN1 structure
--
module Crypto.PubKey.HashDescr
    (
    -- * Types
      HashDescr
    , runHashDescr
    -- * List of known hash description
    , hashDescrMD2
    , hashDescrMD5
    , hashDescrSHA1
    , hashDescrSHA224
    , hashDescrSHA256
    , hashDescrSHA384
    , hashDescrSHA512
    , hashDescrRIPEMD160
    ) where

import           Data.Word
import           Crypto.Hash
import qualified Crypto.Internal.ByteArray as B

--
-- ** Hack **
--
-- this happens to not need a real ASN1 encoder, because
-- thanks to the digest being a specific size AND
-- that the digest data is the last bytes in the encoding,
-- this allows to just prepend the right prefix to the
-- computed digest, to make it in the expected and valid shape.
--
-- Otherwise the expected structure is in the following form:
--
--   Start Sequence
--     ,Start Sequence
--       ,OID oid
--       ,Null
--     ,End Sequence
--     ,OctetString digest
--   ,End Sequence

hashDescr :: (B.ByteArray ba, HashAlgorithm hashAlg)
          => hashAlg -- ^ hash algorithm to use
          -> [Word8] -- ^ the raw DER encoded ASN1 description of hash algorithm followed by the digest to be filled
          -> HashDescr hashAlg ba
hashDescr hashAlg preASN1Descr =
    HashDescr (\input -> B.pack preASN1Descr `B.append` B.convert (hashWith hashAlg input))

-- | A hash methods to generate a ASN.1 structure digest
data HashDescr hashAlg ba = HashDescr { unHashDescr :: ba -> ba }

-- | Run the digest function on some input and get the raw bytes
runHashDescr :: (HashAlgorithm hashAlg, B.ByteArray ba) => HashDescr hashAlg ba -> ba -> ba
runHashDescr h = unHashDescr h

-- | Describe the MD2 hashing algorithm
hashDescrMD2 :: B.ByteArray ba => HashDescr MD2 ba
hashDescrMD2 =
    hashDescr MD2 [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,0x04,0x10]

-- | Describe the MD5 hashing algorithm
hashDescrMD5 :: B.ByteArray ba => HashDescr MD5 ba
hashDescrMD5 =
    hashDescr MD5 [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10]

-- | Describe the SHA1 hashing algorithm
hashDescrSHA1 :: B.ByteArray ba => HashDescr SHA1 ba
hashDescrSHA1 =
    hashDescr SHA1 [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]

-- | Describe the SHA224 hashing algorithm
hashDescrSHA224 :: B.ByteArray ba => HashDescr SHA224 ba
hashDescrSHA224 =
    hashDescr SHA224 [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c]

-- | Describe the SHA256 hashing algorithm
hashDescrSHA256 :: B.ByteArray ba => HashDescr SHA256 ba
hashDescrSHA256 =
    hashDescr SHA256 [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]

-- | Describe the SHA384 hashing algorithm
hashDescrSHA384 :: B.ByteArray ba => HashDescr SHA384 ba
hashDescrSHA384 =
    hashDescr SHA384 [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30]

-- | Describe the SHA512 hashing algorithm
hashDescrSHA512 :: B.ByteArray ba => HashDescr SHA512 ba
hashDescrSHA512 =
    hashDescr SHA512 [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]

-- | Describe the RIPEMD160 hashing algorithm
hashDescrRIPEMD160 :: B.ByteArray ba => HashDescr RIPEMD160 ba
hashDescrRIPEMD160 =
    hashDescr RIPEMD160 [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x24,0x03,0x02,0x01,0x05,0x00,0x04,0x14]
