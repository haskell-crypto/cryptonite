{-# LANGUAGE OverloadedStrings #-}

-- from <http://www.ietf.org/rfc/rfc6070.txt>
module KAT_PBKDF2 (vectors) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

type VectParams = (ByteString, ByteString, Int, Int)

-- PBKDF-HMAC-SHA1
vectors :: [ (VectParams, ByteString) ]
vectors =
    [
        ( ("password","salt",2,20)
        , "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57"
        )
    ,   ( ("password","salt",4096,20)
        , "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1"
        )

    ,   ( ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25)
        , "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38"
        )
    ,   ( ("pass\0word", "sa\0lt", 4096, 16)
        , "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3"
        )
    ]


