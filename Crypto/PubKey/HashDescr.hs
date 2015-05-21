{-# LANGUAGE OverloadedStrings #-}
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
      HashFunction
    , HashDescr(..)
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

import           Data.ByteString.Char8 ()
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.Word
import           Crypto.Hash
import qualified Crypto.Internal.ByteArray as B (convert)

-- | A standard hash function returning a digest object
type HashFunction = ByteString -> ByteString

-- | Describe a hash function and a way to wrap the digest into
-- an DER encoded ASN1 marshalled structure.
data HashDescr = HashDescr { hashFunction :: HashFunction             -- ^ hash function
                           , digestToASN1 :: ByteString -> ByteString -- ^ convertion to an ASN1 wrapped digest bytestring
                           }

-- | Describe the MD2 hashing algorithm
hashDescrMD2 :: HashDescr
hashDescrMD2 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest MD2)
              , digestToASN1 = toHashWithInfo [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,0x04,0x10]
              }
-- | Describe the MD5 hashing algorithm
hashDescrMD5 :: HashDescr
hashDescrMD5 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest MD5)
              , digestToASN1 = toHashWithInfo [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10]
              }
-- | Describe the SHA1 hashing algorithm
hashDescrSHA1 :: HashDescr
hashDescrSHA1 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest SHA1)
              , digestToASN1 = toHashWithInfo [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]
              }
-- | Describe the SHA224 hashing algorithm
hashDescrSHA224 :: HashDescr
hashDescrSHA224 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest SHA224)
              , digestToASN1 = toHashWithInfo [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c]
              }
-- | Describe the SHA256 hashing algorithm
hashDescrSHA256 :: HashDescr
hashDescrSHA256 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest SHA256)
              , digestToASN1 = toHashWithInfo [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
              }
-- | Describe the SHA384 hashing algorithm
hashDescrSHA384 :: HashDescr
hashDescrSHA384 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest SHA384)
              , digestToASN1 = toHashWithInfo [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30]
              }
-- | Describe the SHA512 hashing algorithm
hashDescrSHA512 :: HashDescr
hashDescrSHA512 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest SHA512)
              , digestToASN1 = toHashWithInfo [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]
              }

-- | Describe the RIPEMD160 hashing algorithm
hashDescrRIPEMD160 :: HashDescr
hashDescrRIPEMD160 =
    HashDescr { hashFunction = B.convert . (hash :: ByteString -> Digest RIPEMD160)
              , digestToASN1 = toHashWithInfo [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x24,0x03,0x02,0x01,0x05,0x00,0x04,0x14]
              }

-- | Generate the marshalled structure with the following ASN1 structure:
--
--   Start Sequence
--     ,Start Sequence
--       ,OID oid
--       ,Null
--     ,End Sequence
--     ,OctetString digest
--   ,End Sequence
--
toHashWithInfo :: [Word8] -> ByteString -> ByteString
toHashWithInfo pre digest = B.pack pre `B.append` digest
