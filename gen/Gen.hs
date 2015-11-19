module Main where

import System.FilePath
import System.Directory
import Control.Applicative
import Control.Monad
import Template

readTemplate templateFile = parseTemplate <$> readFile templateFile
writeTemplate file vars multi template = writeFile file (renderTemplate template vars multi)

data GenHashModule = GenHashModule
    { ghmModuleName   :: String
    , ghmHeaderFile   :: String
    , ghmHashName     :: String
    , ghmContextSize  :: Int -- in bytes
    , ghmDigestSize   :: Int -- in bytes
    , ghmBlockLength  :: Int -- in bytes
    , ghmCustomizable :: [(Int, Int)] -- list of (digest output size in *bits*, block size in bytes)
    } deriving (Show,Eq)

hashModules =
    --              module      header        hash        ctx dg blk
    [ GenHashModule "BLAKE2s"   "blake2.h"    "blake2s"   185 256 64  []
    , GenHashModule "BLAKE2sp"  "blake2.h"    "blake2sp"  2185 256 64 []
    , GenHashModule "BLAKE2b"   "blake2.h"    "blake2b"   361 512 128 []
    , GenHashModule "BLAKE2bp"  "blake2.h"    "blake2sp"  2325 512 128 []
    , GenHashModule "MD2"       "md2.h"       "md2"       96  128 16  []
    , GenHashModule "MD4"       "md4.h"       "md4"       96  128 64  []
    , GenHashModule "MD5"       "md5.h"       "md5"       96  128 64  []
    , GenHashModule "SHA1"      "sha1.h"      "sha1"      96  160 64  []
    , GenHashModule "SHA224"    "sha256.h"    "sha224"    192 224 64  []
    , GenHashModule "SHA256"    "sha256.h"    "sha256"    192 256 64  []
    , GenHashModule "SHA384"    "sha512.h"    "sha384"    256 384 128 []
    , GenHashModule "SHA512"    "sha512.h"    "sha512"    256 512 128 []
    , GenHashModule "SHA512t"   "sha512.h"    "sha512t"   264 512 128 [(224,128),(256,128)]
    , GenHashModule "Keccak"    "keccak.h"    "keccak"    360 512 64  [(224,144),(256,136),(384,104),(512,72)]
    , GenHashModule "SHA3"      "sha3.h"      "sha3"      360 512 64  [(224,144),(256,136),(384,104),(512,72)]
    , GenHashModule "RIPEMD160" "ripemd.h"    "ripemd160" 128 160 64  []
    , GenHashModule "Skein256"  "skein256.h"  "skein256"  96  256 32  [(224,32),(256,32)]
    , GenHashModule "Skein512"  "skein512.h"  "skein512"  160 512 64  [(224,64),(256,64),(384,64),(512,64)]
    , GenHashModule "Tiger"     "tiger.h"     "tiger"     96  192 64  []
    , GenHashModule "Whirlpool" "whirlpool.h" "whirlpool" 168 512 64  []
    ]

renderHashModules genOpts = do
    hashTemplate            <- readTemplate "template/hash.hs"
    hashLenTemplate         <- readTemplate "template/hash-len.hs"

    forM_ hashModules $ \ghm -> do
        let vars = [ ("MODULENAME"       , ghmModuleName ghm)
                   , ("HEADER_FILE"      , ghmHeaderFile ghm)
                   , ("HASHNAME"         , ghmHashName ghm)
                   -- context size (compat)
                   , ("SIZECTX"          , show (ghmContextSize ghm))
                   , ("SIZECTX8"         , show (ghmContextSize ghm `div` 8))
                   , ("DIGESTSIZE"       , show (ghmDigestSize ghm `div` 8))
                   , ("BLOCKLEN"         , show (ghmBlockLength ghm))
                   -- context size
                   , ("CTX_SIZE_BYTES"   , show (ghmContextSize ghm))
                   , ("CTX_SIZE_WORD64"  , show (ghmContextSize ghm `div` 8))
                   , ("DIGEST_SIZE_BITS" , show (ghmDigestSize ghm))
                   , ("DIGEST_SIZE_BYTES", show (ghmDigestSize ghm `div` 8))
                   , ("BLOCK_SIZE_BYTES" , show (ghmBlockLength ghm))
                   ] :: Attrs
        let mainDir      = "Crypto/Hash"
            mainName     = mainDir </> (ghmModuleName ghm ++ ".hs")

        createDirectoryIfMissing True mainDir

        let tpl =
                if not $ null $ ghmCustomizable ghm
                    then hashLenTemplate
                    else hashTemplate
        let multi = [ ("CUSTOMIZABLE", map (\(outputSizeBits, customBlockSize) ->
                        [ ("CUSTOM_BITSIZE", show outputSizeBits)
                        , ("CUSTOM_DIGEST_SIZE_BITS", show outputSizeBits)
                        , ("CUSTOM_DIGEST_SIZE_BYTES", show (outputSizeBits `div` 8))
                        , ("CUSTOM_BLOCK_SIZE_BYTES", show customBlockSize)
                        ]) (ghmCustomizable ghm)
                      )
                    ] :: [(String, [Attrs])]

        writeTemplate mainName vars multi tpl

main = do
    renderHashModules ()
