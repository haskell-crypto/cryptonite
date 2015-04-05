module BlockCipher
    ( KAT_ECB(..)
    , KAT_CBC(..)
    , KAT_CFB(..)
    , KAT_CTR(..)
    , KAT_XTS(..)
    , KAT_AEAD(..)
    , testECB
    , testKatCBC
    , testKatCFB
    , testKatCTR
    , testKatXTS
    , testKatAEAD
    , CipherInfo
    ) where

import Imports

type BlockSize = Int
type KeySize = Int
type CipherInfo a = (BlockSize, KeySize, ByteString -> a)

-- | ECB KAT
data KAT_ECB = KAT_ECB
    { ecbKey        :: ByteString -- ^ Key
    , ecbPlaintext  :: ByteString -- ^ Plaintext
    , ecbCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CBC KAT
data KAT_CBC = KAT_CBC
    { cbcKey        :: ByteString -- ^ Key
    , cbcIV         :: ByteString -- ^ IV
    , cbcPlaintext  :: ByteString -- ^ Plaintext
    , cbcCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CFB KAT
data KAT_CFB = KAT_CFB
    { cfbKey        :: ByteString -- ^ Key
    , cfbIV         :: ByteString -- ^ IV
    , cfbPlaintext  :: ByteString -- ^ Plaintext
    , cfbCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CTR KAT
data KAT_CTR = KAT_CTR
    { ctrKey        :: ByteString -- ^ Key
    , ctrIV         :: ByteString -- ^ IV (usually represented as a 128 bits integer)
    , ctrPlaintext  :: ByteString -- ^ Plaintext 
    , ctrCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | XTS KAT
data KAT_XTS = KAT_XTS
    { xtsKey1       :: ByteString -- ^ 1st XTS key
    , xtsKey2       :: ByteString -- ^ 2nd XTS key
    , xtsIV         :: ByteString -- ^ XTS IV
    , xtsPlaintext  :: ByteString -- ^ plaintext
    , xtsCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | AEAD KAT
data KAT_AEAD = KAT_AEAD
    { aeadKey        :: ByteString -- ^ Key
    , aeadIV         :: ByteString -- ^ IV for initialization
    , aeadHeader     :: ByteString -- ^ Authentificated Header
    , aeadPlaintext  :: ByteString -- ^ Plaintext
    , aeadCiphertext :: ByteString -- ^ Ciphertext
    , aeadTaglen     :: Int        -- ^ aead tag len
    , aeadTag        :: ByteString -- ^ expected tag
    } deriving (Show,Eq)

testECB (_, _, cipherInit) ecbEncrypt ecbDecrypt kats =
    testGroup "ECB" (concatMap katTest (zip is kats) {- ++ propTests-})
  where katTest (i,d) =
            [ testCase ("E" ++ show i) (ecbEncrypt ctx (ecbPlaintext d) @?= ecbCiphertext d)
            , testCase ("D" ++ show i) (ecbDecrypt ctx (ecbCiphertext d) @?= ecbPlaintext d)
            ]
          where ctx = cipherInit (ecbKey d)
        --propTest = testProperty "decrypt.encrypt" (ECBUnit key plaintext) =
        
        --testProperty_ECB (ECBUnit (cipherInit -> ctx) (toBytes -> plaintext)) =
        --    plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

testKatCBC cbcInit cbcEncrypt cbcDecrypt (i,d) =
    [ testCase ("E" ++ show i) (cbcEncrypt ctx iv (cbcPlaintext d) @?= cbcCiphertext d)
    , testCase ("D" ++ show i) (cbcDecrypt ctx iv (cbcCiphertext d) @?= cbcPlaintext d)
    ]
  where ctx = cbcInit $ cbcKey d
        iv  = cbcIV d

testKatCFB cfbInit cfbEncrypt cfbDecrypt (i,d) =
    [ testCase ("E" ++ show i) (cfbEncrypt ctx iv (cfbPlaintext d) @?= cfbCiphertext d)
    , testCase ("D" ++ show i) (cfbDecrypt ctx iv (cfbCiphertext d) @?= cfbPlaintext d)
    ]
  where ctx = cfbInit $ cfbKey d
        iv  = cfbIV d

testKatCTR ctrInit ctrCombine (i,d) =
    [ testCase ("E" ++ i) (ctrCombine ctx iv (ctrPlaintext d) @?= ctrCiphertext d)
    , testCase ("D" ++ i) (ctrCombine ctx iv (ctrCiphertext d) @?= ctrPlaintext d)
    ]
  where ctx = ctrInit $ ctrKey d
        iv  = ctrIV d

testKatXTS xtsInit xtsEncrypt xtsDecrypt (i,d) =
    [ testCase ("E" ++ i) (xtsEncrypt ctx iv 0 (xtsPlaintext d) @?= xtsCiphertext d)
    , testCase ("D" ++ i) (xtsDecrypt ctx iv 0 (xtsCiphertext d) @?= xtsPlaintext d)
    ]
  where ctx  = xtsInit (xtsKey1 d, xtsKey2 d)
        iv   = xtsIV d

testKatAEAD cipherInit aeadInit aeadAppendHeader aeadEncrypt aeadDecrypt aeadFinalize (i,d) =
    [ testCase ("AE" ++ i) (etag @?= aeadTag d)
    , testCase ("AD" ++ i) (dtag @?= aeadTag d)
    , testCase ("E" ++ i)  (ebs @?= aeadCiphertext d)
    , testCase ("D" ++ i)  (dbs @?= aeadPlaintext d)
    ]
  where ctx              = cipherInit $ aeadKey d
        (Just aead)      = aeadInit ctx (aeadIV d)
        aeadHeaded       = aeadAppendHeader aead (aeadHeader d)
        (ebs,aeadEFinal) = aeadEncrypt aeadHeaded (aeadPlaintext d)
        (dbs,aeadDFinal) = aeadDecrypt aeadHeaded (aeadCiphertext d)
        etag = aeadFinalize aeadEFinal (aeadTaglen d)
        dtag = aeadFinalize aeadDFinal (aeadTaglen d)

is :: [Int]
is = [1..]
