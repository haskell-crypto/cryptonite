-- Test vectors are taken from GEC2: www.secg.org/collateral/gec2.pdf
{-# LANGUAGE OverloadedStrings #-}
module KAT_PubKey.ECDSA (ecdsaTests) where

import Crypto.Number.Serialize

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import Crypto.Hash (SHA1(..))

import Imports

data VectorECDSA = VectorECDSA
    { curve :: ECC.Curve
    , msg   :: ByteString
    , d     :: Integer
    , q     :: ECC.Point
    , k     :: Integer
    , r     :: Integer
    , s     :: Integer
    }

vectorsSHA1 =
    [ VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_p160r1
        , msg   = "abc"
        , d     = 971761939728640320549601132085879836204587084162
        , q     = ECC.Point 466448783855397898016055842232266600516272889280
                            1110706324081757720403272427311003102474457754220
        , k     = 702232148019446860144825009548118511996283736794
        , r     = 1176954224688105769566774212902092897866168635793
        , s     = 299742580584132926933316745664091704165278518100
        }
    -- from official ECDSA KATs
    , VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_t163k1
        , msg   = i2osp 0xa2c1a03fdd00521bb08fc88d20344321977aaf637ef9d5470dd7d2c8628fc8d0d1f1d3587c6b3fd02386f8c13db341b14748a9475cc63baf065df64054b27d5c2cdf0f98e3bbb81d0b5dc94f8cdb87acf75720f6163de394c8c6af360bc1acb85b923a493b7b27cc111a257e36337bd94eb0fab9d5e633befb1ae7f1b244bfaa
        , d     = 0x00000011f2626d90d26cb4c0379043b26e64107fc
        , q     = ECC.Point 0x0389fa5ad7f8304325a8c060ef7dcb83042c045bc
                            0x0eefa094a5054da196943cc80509dcb9f59e5bc2e
        , k     = 0x0000000c3a4ff97286126dab1e5089395fcc47ebb
        , r     = 0x0dbe6c3a1dc851e7f2338b5c26c62b4b37bf8035c
        , s     = 0x1c76458135b1ff9fbd23009b8414a47996126b56a
        }
    , VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_t163k1
        , msg   = i2osp 0x67048080daaeb77d3ac31babdf8be23dbe75ceb4dfb94aa8113db5c5dcb6fe14b70f717b7b0ed0881835a66a86e6d840ffcb7d976c75ef2d1d4322fbbc86357384e24707aef88cea2c41a01a9a3d1b9e72ce650c7fdecc4f9448d3a77df6cdf13647ab295bb3132de0b1b2c402d8d2de7d452f1e003e0695de1470d1064eee16
        , d     = 0x00000006a3803301daee9af09bb5b6c991a4f49a4
        , q     = ECC.Point 0x4b500f555e857da8c299780130c5c3f48f02ee322 0x5c1c0ae25b47f06cc46fb86b12d2d8c0ba6a4bf07
        , k     = 0x0000002f39fbf77f3e0dc046116de692b6cf91b16
        , r     = 0x3d3eeda42f65d727f4a564f1415654356c6c57a6c
        , s     = 0x35e4d43c5f08baddf138449db1ad0b7872552b7cd
        }
    , VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_t163k1
        , msg   = i2osp 0x77e007dc2acd7248256165a4b30e98986f51a81efd926b85f74c81bc2a6d2bcd030060a844091e22fbb0ff3db5a20caaefb5d58ccdcbc27f0ff8a4d940e78f303079ec1ca5b0ca3d4ecc7580f8b34a9f0496c9e719d2ec3e1614b7644bc11179e895d2c0b58a1da204fbf0f6e509f97f983eacb6487092caf6e8e4e6b3c458b2
        , d     = 0x0000002e28676514bd93fea11b62db0f6e324b18d
        , q     = ECC.Point 0x3f9c90b71f6a1de20a2716f38ef1b5f98c757bd42 0x2ff0a5d266d447ef62d43fbca6c34c08c1ce35a40
        , k     = 0x00000001233ae699883e74e7f4dfb5279ff22280a
        , r     = 0x39de3cd2cf04145e522b8fba3f23e9218226e0860
        , s     = 0x2af62bfb3cfa202e2342606ee5bb0934c3b0375b6
        }
    , VectorECDSA
        { curve = ECC.getCurveByName ECC.SEC_t163k1
        , msg   = i2osp 0xfbacfcce4688748406ddf5c3495021eef8fb399865b649eb2395a04a1ab28335da2c236d306fcc59f7b65ea931cf0139571e1538ede5688958c3ac69f47a285362f5ad201f89cc735b7b465408c2c41b310fc8908d0be45054df2a7351fae36b390e842f3b5cdd9ad832940df5b2d25c2ed43ce86eaf2508bcf401ae58bb1d47
        , d     = 0x000000361dd088e3a6d3c910686c8dce57e5d4d8e
        , q     = ECC.Point 0x064f905c1da9d7e9c32d81890ae6f30dcc7839d32 0x06f1faedb6d9032016d3b681e7cf69c29d29eb27b
        , k     = 0x00000022f723e9f5da56d3d0837d5dca2f937395f
        , r     = 0x374cdc8571083fecfbd4e25e1cd69ecc66b715f2d
        , s     = 0x313b10949222929b2f20b15d446c27d6dcae3f086
        }
    ]

vectorToPrivate :: VectorECDSA -> ECDSA.PrivateKey
vectorToPrivate vector = ECDSA.PrivateKey (curve vector) (d vector)

vectorToPublic :: VectorECDSA -> ECDSA.PublicKey
vectorToPublic vector = ECDSA.PublicKey (curve vector) (q vector)

doSignatureTest hashAlg (i, vector) = testCase (show i) (expected @=? actual)
  where expected = Just $ ECDSA.Signature (r vector) (s vector)
        actual   = ECDSA.signWith (k vector) (vectorToPrivate vector) hashAlg (msg vector)

doVerifyTest hashAlg (i, vector) = testCase (show i) (True @=? actual)
  where actual = ECDSA.verify hashAlg (vectorToPublic vector) (ECDSA.Signature (r vector) (s vector)) (msg vector)

ecdsaTests = testGroup "ECDSA"
    [ testGroup "SHA1"
        [ testGroup "signature" $ map (doSignatureTest SHA1) (zip [katZero..] vectorsSHA1)
        , testGroup "verify" $ map (doVerifyTest SHA1) (zip [katZero..] vectorsSHA1)
        ]
    ]
