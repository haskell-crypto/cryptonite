{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Main where

import System.FilePath
import System.Directory
import Control.Applicative
import Control.Monad
import Template

readTemplate templateFile = parseTemplate <$> readFile templateFile
writeTemplate file vars multi template = writeFile file (renderTemplate template vars multi)

-- print a loud error if the conversion is losing information
divSafe :: Int -> Int -> Int
divSafe a b
    | r == 0    = d
    | otherwise = error ("cannot safely convert values: trying to divide " ++ show a ++ " by " ++ show b ++ " remainder: " ++ show r)
  where
    (d,r) = a `divMod` b

newtype Bits = Bits Int
    deriving (Show,Eq,Num)
newtype Bytes = Bytes Int
    deriving (Show,Eq,Num)

class SizedNum a where
    showBytes :: a -> String
    showBits  :: a -> String
    showW64   :: a -> String

instance SizedNum Bytes where
    showBits (Bytes b)  = show (b * 8)
    showBytes (Bytes b) = show b
    showW64 (Bytes b)   = show (b `divSafe` 8)
instance SizedNum Bits where
    showBits (Bits b)  = show b
    showBytes (Bits b) = show (b `divSafe` 8)
    showW64 (Bits b)  = show (b `divSafe` 64)

data GenHashModule = GenHashModule
    { ghmModuleName   :: String
    , ghmHeaderFile   :: String
    , ghmHashName     :: String
    , ghmContextSize  :: Bytes
    , ghmCustomizable :: HashCustom
    } deriving (Show,Eq)

data HashCustom =
      HashSimple Bits -- digest size in bits
                 Bytes -- block length in bytes
    | HashMulti [(Bits, Bytes)] -- list of (digest output size in *bits*, block size in bytes)
    deriving (Show,Eq)

hashModules =
    --              module      header        hash        ctx dg blk
    [ GenHashModule "BLAKE2s"   "blake2.h"    "blake2s"   185  (HashSimple 256 64)
    , GenHashModule "BLAKE2sp"  "blake2.h"    "blake2sp"  2185 (HashSimple 256 64)
    , GenHashModule "BLAKE2b"   "blake2.h"    "blake2b"   361  (HashSimple 512 128)
    , GenHashModule "BLAKE2bp"  "blake2.h"    "blake2sp"  2325 (HashSimple 512 128)
    , GenHashModule "MD2"       "md2.h"       "md2"       96   (HashSimple 128 16)
    , GenHashModule "MD4"       "md4.h"       "md4"       96   (HashSimple 128 64)
    , GenHashModule "MD5"       "md5.h"       "md5"       96   (HashSimple 128 64)
    , GenHashModule "SHA1"      "sha1.h"      "sha1"      96   (HashSimple 160 64)
    , GenHashModule "SHA224"    "sha256.h"    "sha224"    192  (HashSimple 224 64)
    , GenHashModule "SHA256"    "sha256.h"    "sha256"    192  (HashSimple 256 64)
    , GenHashModule "SHA384"    "sha512.h"    "sha384"    256  (HashSimple 384 128)
    , GenHashModule "SHA512"    "sha512.h"    "sha512"    256  (HashSimple 512 128)
    , GenHashModule "SHA512t"   "sha512.h"    "sha512t"   256  (HashMulti [(224,128),(256,128)])
    , GenHashModule "Keccak"    "keccak.h"    "keccak"    352  (HashMulti [(224,144),(256,136),(384,104),(512,72)])
    , GenHashModule "SHA3"      "sha3.h"      "sha3"      352  (HashMulti [(224,144),(256,136),(384,104),(512,72)])
    , GenHashModule "RIPEMD160" "ripemd.h"    "ripemd160" 128  (HashSimple 160 64)
    , GenHashModule "Skein256"  "skein256.h"  "skein256"  96   (HashMulti [(224,32),(256,32)])
    , GenHashModule "Skein512"  "skein512.h"  "skein512"  160  (HashMulti [(224,64),(256,64),(384,64),(512,64)])
    , GenHashModule "Tiger"     "tiger.h"     "tiger"     96   (HashSimple 192 64)
    , GenHashModule "Whirlpool" "whirlpool.h" "whirlpool" 168  (HashSimple 512 64)
    ]

renderHashModules genOpts = do
    hashTemplate            <- readTemplate "template/hash.hs"
    hashLenTemplate         <- readTemplate "template/hash-len.hs"

    forM_ hashModules $ \ghm -> do
        let baseVars = [ ("MODULENAME"       , ghmModuleName ghm)
                       , ("HEADER_FILE"      , ghmHeaderFile ghm)
                       , ("HASHNAME"         , ghmHashName ghm)
                       , ("CTX_SIZE_BYTES"   , showBytes (ghmContextSize ghm))
                       , ("CTX_SIZE_WORD64"  , showW64 (ghmContextSize ghm))
                       ] :: Attrs
        let mainDir      = "Crypto/Hash"
            mainName     = mainDir </> (ghmModuleName ghm ++ ".hs")

        createDirectoryIfMissing True mainDir

        let (tpl, addVars, multiVars) =
                case ghmCustomizable ghm of
                    HashSimple digestSize blockLength ->
                        (hashTemplate,
                            [ ("DIGEST_SIZE_BITS" , showBits digestSize)
                            , ("DIGEST_SIZE_BYTES", showBytes digestSize)
                            , ("BLOCK_SIZE_BYTES" , showBytes blockLength)
                            ]
                        , []
                        )
                    HashMulti customSizes ->
                        (hashLenTemplate, [],
                            [ ("CUSTOMIZABLE", map (\(outputSizeBits, customBlockSize) ->
                                [ ("CUSTOM_BITSIZE", showBits outputSizeBits)
                                , ("CUSTOM_DIGEST_SIZE_BITS", showBits outputSizeBits)
                                , ("CUSTOM_DIGEST_SIZE_BYTES", showBytes outputSizeBits)
                                , ("CUSTOM_BLOCK_SIZE_BYTES", showBytes customBlockSize)
                                ]) customSizes
                              )
                            ]
                        )

        writeTemplate mainName (baseVars ++ addVars) multiVars tpl

main = do
    renderHashModules ()
