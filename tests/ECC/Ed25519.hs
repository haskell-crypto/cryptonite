{-# LANGUAGE OverloadedStrings #-}
module ECC.Ed25519 ( tests ) where

import           Crypto.Error
import qualified Crypto.ECC.Ed25519 as Ed25519
import           Imports

instance Arbitrary Ed25519.Scalar where
    arbitrary = fmap (throwCryptoError . Ed25519.scalarDecodeLong)
                     (arbitraryBS 32)

instance Arbitrary Ed25519.Point where
    arbitrary = Ed25519.toPoint `fmap` arbitrary

tests = testGroup "ECC.Ed25519"
    [ testGroup "vectors"
        [ testCase "11*G"         $ p011 @=? Ed25519.toPoint s011
        , testCase "123*G"        $ p123 @=? Ed25519.toPoint s123
        , testCase "134*G"        $ p134 @=? Ed25519.toPoint s134
        , testCase "123*G + 11*G" $ p134 @=? Ed25519.pointAdd p123 p011
        ]
    , testGroup "scalar arithmetic"
        [ testProperty "scalarDecodeLong.scalarEncode==id" $ \s ->
            let bs = Ed25519.scalarEncode s :: ByteString
                ss = Ed25519.scalarDecodeLong bs
             in CryptoPassed s `propertyEq` ss
        , testCase "curve order" $ s0 @=? sN
        , testProperty "addition with zero" $ \s ->
            propertyHold [ eqTest "zero left"  s (Ed25519.scalarAdd s0 s)
                         , eqTest "zero right" s (Ed25519.scalarAdd s s0)
                         ]
        , testProperty "addition associative" $ \sa sb sc ->
            Ed25519.scalarAdd sa (Ed25519.scalarAdd sb sc) === Ed25519.scalarAdd (Ed25519.scalarAdd sa sb) sc
        , testProperty "addition commutative" $ \sa sb ->
            Ed25519.scalarAdd sa sb === Ed25519.scalarAdd sb sa
        , testProperty "multiplication with zero" $ \s ->
            propertyHold [ eqTest "zero left"  s0 (Ed25519.scalarMul s0 s)
                         , eqTest "zero right" s0 (Ed25519.scalarMul s s0)
                         ]
        , testProperty "multiplication with one" $ \s ->
            propertyHold [ eqTest "one left"  s (Ed25519.scalarMul s1 s)
                         , eqTest "one right" s (Ed25519.scalarMul s s1)
                         ]
        , testProperty "multiplication associative" $ \sa sb sc ->
            Ed25519.scalarMul sa (Ed25519.scalarMul sb sc) === Ed25519.scalarMul (Ed25519.scalarMul sa sb) sc
        , testProperty "multiplication commutative" $ \sa sb ->
            Ed25519.scalarMul sa sb === Ed25519.scalarMul sb sa
        , testProperty "multiplication distributive" $ \sa sb sc ->
            propertyHold [ eqTest "distributive left"  ((sa `Ed25519.scalarMul` sb) `Ed25519.scalarAdd` (sa `Ed25519.scalarMul` sc))
                                                       (sa `Ed25519.scalarMul` (sb `Ed25519.scalarAdd` sc))
                         , eqTest "distributive right" ((sb `Ed25519.scalarMul` sa) `Ed25519.scalarAdd` (sc `Ed25519.scalarMul` sa))
                                                       ((sb `Ed25519.scalarAdd` sc) `Ed25519.scalarMul` sa)
                         ]
        ]
    , testGroup "point arithmetic"
        [ testProperty "pointDecode.pointEncode==id" $ \p ->
            let bs = Ed25519.pointEncode p :: ByteString
                p' = Ed25519.pointDecode bs
             in CryptoPassed p `propertyEq` p'
        , testProperty "pointEncode.pointDecode==id" $ \p ->
            let b  = Ed25519.pointEncode p :: ByteString
                p' = Ed25519.pointDecode b
                b' = Ed25519.pointEncode `fmap` p'
             in CryptoPassed b `propertyEq` b'
        , testProperty "addition with identity" $ \p ->
            propertyHold [ eqTest "identity left"  p (Ed25519.pointAdd p0 p)
                         , eqTest "identity right" p (Ed25519.pointAdd p p0)
                         ]
        , testProperty "addition associative" $ \pa pb pc ->
            Ed25519.pointAdd pa (Ed25519.pointAdd pb pc) === Ed25519.pointAdd (Ed25519.pointAdd pa pb) pc
        , testProperty "addition commutative" $ \pa pb ->
            Ed25519.pointAdd pa pb === Ed25519.pointAdd pb pa
        , testProperty "negation" $ \p ->
            p0 `propertyEq` Ed25519.pointAdd p (Ed25519.pointNegate p)
        , testProperty "doubling" $ \p ->
            Ed25519.pointAdd p p `propertyEq` Ed25519.pointDouble p
        , testProperty "scalarmult with zero" $ \p ->
            p0 `propertyEq` Ed25519.pointMul s0 p
        , testProperty "scalarmult with one" $ \p ->
            p `propertyEq` Ed25519.pointMul s1 p
        , testProperty "scalarmult with two" $ \p ->
            Ed25519.pointDouble p `propertyEq` Ed25519.pointMul s2 p
        , testProperty "scalarmult with curve order - 1" $ \p ->
            Ed25519.pointNegate p `propertyEq` Ed25519.pointMul sI p
        , testProperty "scalarmult commutative" $ \a b ->
            Ed25519.pointMul a (Ed25519.toPoint b) === Ed25519.pointMul b (Ed25519.toPoint a)
        , testProperty "scalarmult distributive" $ \x y p ->
            let pR = Ed25519.pointMul x p `Ed25519.pointAdd` Ed25519.pointMul y p
             in pR `propertyEq` Ed25519.pointMul (x `Ed25519.scalarAdd` y) p
        ]
    ]
  where
    p0 = Ed25519.toPoint s0
    CryptoPassed s0 = Ed25519.scalarDecodeLong ("" :: ByteString)
    CryptoPassed s1 = Ed25519.scalarDecodeLong ("\x01" :: ByteString)
    CryptoPassed s2 = Ed25519.scalarDecodeLong ("\x02" :: ByteString)
    CryptoPassed sI = Ed25519.scalarDecodeLong ("\236\211\245\\\SUBc\DC2X\214\156\247\162\222\249\222\DC4\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\DLE" :: ByteString)
    CryptoPassed sN = Ed25519.scalarDecodeLong ("\237\211\245\\\SUBc\DC2X\214\156\247\162\222\249\222\DC4\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\DLE" :: ByteString)

    CryptoPassed s011 = Ed25519.scalarDecodeLong ("\011" :: ByteString)
    CryptoPassed s123 = Ed25519.scalarDecodeLong ("\123" :: ByteString)
    CryptoPassed s134 = Ed25519.scalarDecodeLong ("\134" :: ByteString)

    CryptoPassed p011 = Ed25519.pointDecode ("\x13\x37\x03\x6a\xc3\x2d\x8f\x30\xd4\x58\x9c\x3c\x1c\x59\x58\x12\xce\x0f\xff\x40\xe3\x7c\x6f\x5a\x97\xab\x21\x3f\x31\x82\x90\xad" :: ByteString)
    CryptoPassed p123 = Ed25519.pointDecode ("\xc4\xb8\x00\xc8\x70\x10\xf9\x46\x83\x03\xde\xea\x87\x65\x03\xe8\x86\xbf\xde\x19\x00\xe9\xe8\x46\xfd\x4c\x3c\xd0\x9c\x1c\xbc\x9f" :: ByteString)
    CryptoPassed p134 = Ed25519.pointDecode ("\x51\x20\xab\xe0\x3c\xa2\xaf\x66\xc7\x7c\xa3\x20\xf0\xb2\x1f\xb5\x56\xf6\xb6\x5f\xdd\x7e\x32\x64\xc1\x4a\x30\xd9\x7b\xf7\xa7\x6f" :: ByteString)

    -- Using <http://ed25519.cr.yp.to/python/ed25519.py>:
    --
    -- >>> import ed25519
    -- >>> ed25519.encodepoint(ed25519.scalarmult(ed25519.B, 11)).encode('hex')
    -- '1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad'
    -- >>> ed25519.encodepoint(ed25519.scalarmult(ed25519.B, 123)).encode('hex')
    -- 'c4b800c87010f9468303deea876503e886bfde1900e9e846fd4c3cd09c1cbc9f'
    -- >>> ed25519.encodepoint(ed25519.scalarmult(ed25519.B, 134)).encode('hex')
    -- '5120abe03ca2af66c77ca320f0b21fb556f6b65fdd7e3264c14a30d97bf7a76f'
