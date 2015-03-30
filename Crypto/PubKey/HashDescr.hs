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

import Data.ByteString (ByteString)
import Data.Byteable (toBytes)
import qualified Data.ByteString as B
import Crypto.Hash

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
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest MD2)
              , digestToASN1 = toHashWithInfo "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10"
              }
-- | Describe the MD5 hashing algorithm
hashDescrMD5 :: HashDescr
hashDescrMD5 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest MD5)
              , digestToASN1 = toHashWithInfo "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"
              }
-- | Describe the SHA1 hashing algorithm
hashDescrSHA1 :: HashDescr
hashDescrSHA1 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest SHA1)
              , digestToASN1 = toHashWithInfo "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
              }
-- | Describe the SHA224 hashing algorithm
hashDescrSHA224 :: HashDescr
hashDescrSHA224 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest SHA224)
              , digestToASN1 = toHashWithInfo "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c"
              }
-- | Describe the SHA256 hashing algorithm
hashDescrSHA256 :: HashDescr
hashDescrSHA256 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest SHA256)
              , digestToASN1 = toHashWithInfo "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
              }
-- | Describe the SHA384 hashing algorithm
hashDescrSHA384 :: HashDescr
hashDescrSHA384 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest SHA384)
              , digestToASN1 = toHashWithInfo "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
              }
-- | Describe the SHA512 hashing algorithm
hashDescrSHA512 :: HashDescr
hashDescrSHA512 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest SHA512)
              , digestToASN1 = toHashWithInfo "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
              }

-- | Describe the RIPEMD160 hashing algorithm
hashDescrRIPEMD160 :: HashDescr
hashDescrRIPEMD160 =
    HashDescr { hashFunction = toBytes . (hash :: ByteString -> Digest RIPEMD160)
              , digestToASN1 = toHashWithInfo "\x30\x21\x30\x09\x06\x05\x2b\x24\x03\x02\x01\x05\x00\x04\x14"
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
toHashWithInfo :: ByteString -> ByteString -> ByteString
toHashWithInfo pre digest = pre `B.append` digest
