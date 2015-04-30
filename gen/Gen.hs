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
    , ghmContextSize  :: Int
    , ghmDigestSize   :: Int
    , ghmBlockLength  :: Int
    , ghmCustomizable :: [(Int, Int)]
    } deriving (Show,Eq)

hashModules =
    --              module      header        hash        ctx dg blk
    [ GenHashModule "MD2"       "md2.h"       "md2"       96  16 16  []
    , GenHashModule "MD4"       "md4.h"       "md4"       96  16 64  []
    , GenHashModule "MD5"       "md5.h"       "md5"       96  16 64  []
    , GenHashModule "SHA1"      "sha1.h"      "sha1"      96  20 64  []
    , GenHashModule "SHA224"    "sha256.h"    "sha224"    192 28 64  []
    , GenHashModule "SHA256"    "sha256.h"    "sha256"    192 32 64  []
    , GenHashModule "SHA384"    "sha512.h"    "sha384"    256 48 128 []
    , GenHashModule "SHA512"    "sha512.h"    "sha512"    256 64 128 []
    , GenHashModule "Kekkak"    "kekkak.h"    "kekkak"    360 64 64  [(224,144),(256,136),(384,104),(512,72)]
    , GenHashModule "SHA3"      "sha3.h"      "sha3"      360 64 64  [(224,144),(256,136),(384,104),(512,72)]
    , GenHashModule "RIPEMD160" "ripemd.h"    "ripemd160" 128 20 64  []
    , GenHashModule "Skein256"  "skein256.h"  "skein256"  96  32 32  [(224,32),(256,32)]
    , GenHashModule "Skein512"  "skein512.h"  "skein512"  160 64 64  [(224,64),(256,64),(384,64),(512,64)]
    , GenHashModule "Tiger"     "tiger.h"     "tiger"     96  24 64  []
    , GenHashModule "Whirlpool" "whirlpool.h" "whirlpool" 168 64 64  []
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
                   , ("DIGESTSIZE"       , show (ghmDigestSize ghm))
                   , ("BLOCKLEN"         , show (ghmBlockLength ghm))
                   -- context size
                   , ("CTX_SIZE_BYTES"   , show (ghmContextSize ghm))
                   , ("CTX_SIZE_WORD64"  , show (ghmContextSize ghm `div` 8))
                   , ("DIGEST_SIZE_BITS" , show (ghmDigestSize ghm * 8))
                   , ("DIGEST_SIZE_BYTES", show (ghmDigestSize ghm))
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
