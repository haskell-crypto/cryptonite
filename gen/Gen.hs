module Main where

import System.FilePath
import System.Directory
import Control.Applicative
import Control.Monad
import Template

readTemplate templateFile = parseTemplate <$> readFile templateFile
writeTemplate file vars template = writeFile file (renderTemplate template vars)

data GenHashModule = GenHashModule
    { ghmModuleName   :: String
    , ghmHeaderFile   :: String
    , ghmHashName     :: String
    , ghmContextSize  :: Int
    , ghmDigestSize   :: Int
    , ghmBlockLength  :: Int
    , ghmCustomizable :: Bool
    } deriving (Show,Eq)

hashModules =
    [ GenHashModule "MD2"       "md2.h"       "md2"       96  16 16  False
    , GenHashModule "MD4"       "md4.h"       "md4"       96  16 64  False
    , GenHashModule "MD5"       "md5.h"       "md5"       96  16 64  False
    , GenHashModule "SHA1"      "sha1.h"      "sha1"      96  20 64  False
    , GenHashModule "SHA224"    "sha256.h"    "sha224"    192 28 64  False
    , GenHashModule "SHA256"    "sha256.h"    "sha256"    192 32 64  False
    , GenHashModule "SHA384"    "sha512.h"    "sha384"    256 48 128 False
    , GenHashModule "SHA512"    "sha512.h"    "sha512"    256 64 128 False
    , GenHashModule "Kekkak"    "kekkak.h"    "kekkak"    360 64 64  True
    , GenHashModule "SHA3"      "sha3.h"      "sha3"      360 64 64  True
    , GenHashModule "RIPEMD160" "ripemd.h"    "ripemd160" 128 20 64  False
    , GenHashModule "Skein256"  "skein256.h"  "skein256"  96  32 32  True
    , GenHashModule "Skein512"  "skein512.h"  "skein512"  160 64 64  True
    , GenHashModule "Tiger"     "tiger.h"     "tiger"     96  24 64  False
    , GenHashModule "Whirlpool" "whirlpool.h" "whirlpool" 168 64 64  False
    ]

renderHashModules genOpts = do
    hashTemplate            <- readTemplate "template/hash.hs"
    hashInternalTemplate    <- readTemplate "template/hash-internal.hs"
    hashLenTemplate         <- readTemplate "template/hash-len.hs"
    hashLenInternalTemplate <- readTemplate "template/hash-internal-len.hs"

    forM_ hashModules $ \ghm -> do
        let vars = [ ("MODULENAME", ghmModuleName ghm)
                   , ("HEADER_FILE", ghmHeaderFile ghm)
                   , ("HASHNAME", ghmHashName ghm)
                   , ("SIZECTX", show (ghmContextSize ghm))
                   , ("DIGESTSIZE", show (ghmDigestSize ghm))
                   , ("SIZECTX8", show (ghmContextSize ghm `div` 8))
                   , ("BLOCKLEN", show (ghmBlockLength ghm))
                   ]
        let mainDir      = "Crypto/Hash"
            internalDir  = "Crypto/Hash/Internal"
            mainName     = mainDir </> (ghmModuleName ghm ++ ".hs")
            internalName = internalDir </> (ghmModuleName ghm ++ ".hs")

        createDirectoryIfMissing True mainDir
        createDirectoryIfMissing True internalDir

        if ghmCustomizable ghm
            then do writeTemplate mainName vars hashLenTemplate
                    writeTemplate internalName vars hashLenInternalTemplate
            else do writeTemplate mainName vars hashTemplate
                    writeTemplate internalName vars hashInternalTemplate

main = do
    renderHashModules ()
