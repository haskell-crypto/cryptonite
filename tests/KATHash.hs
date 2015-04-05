{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
module KATHash
    ( tests
    ) where


import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA512t as SHA512t
import qualified Crypto.Hash.SHA3 as SHA3
import qualified Crypto.Hash.Kekkak as Kekkak
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512
import qualified Crypto.Hash.Whirlpool as Whirlpool

import qualified Data.ByteString as B
import Imports

v0,v1,v2 :: ByteString
v0 = ""
v1 = "The quick brown fox jumps over the lazy dog"
v2 = "The quick brown fox jumps over the lazy cog"
vectors = [ v0, v1, v2 ]

instance Arbitrary ByteString where
    arbitrary = B.pack `fmap` arbitrary

data HashFct = HashFct
    { fctHash   :: (B.ByteString -> B.ByteString)
    , fctInc    :: ([B.ByteString] -> B.ByteString) }

hashinc i u f = f . foldl u i

md2Hash    = HashFct { fctHash = MD2.hash, fctInc = hashinc MD2.init MD2.update MD2.finalize }
md4Hash    = HashFct { fctHash = MD4.hash, fctInc = hashinc MD4.init MD4.update MD4.finalize }
md5Hash    = HashFct { fctHash = MD5.hash, fctInc = hashinc MD5.init MD5.update MD5.finalize }

sha1Hash   = HashFct { fctHash = SHA1.hash, fctInc = hashinc SHA1.init SHA1.update SHA1.finalize }

sha224Hash = HashFct { fctHash = SHA224.hash, fctInc = hashinc SHA224.init SHA224.update SHA224.finalize }
sha256Hash = HashFct { fctHash = SHA256.hash, fctInc = hashinc SHA256.init SHA256.update SHA256.finalize }

sha384Hash = HashFct { fctHash = SHA384.hash, fctInc = hashinc SHA384.init SHA384.update SHA384.finalize }
sha512Hash = HashFct { fctHash = SHA512.hash, fctInc = hashinc SHA512.init SHA512.update SHA512.finalize }
sha512_224Hash = HashFct { fctHash = SHA512t.hash 224, fctInc = hashinc (SHA512t.init 224) SHA512t.update SHA512t.finalize }
sha512_256Hash = HashFct { fctHash = SHA512t.hash 256, fctInc = hashinc (SHA512t.init 256) SHA512t.update SHA512t.finalize }

sha3Hash i = HashFct { fctHash = SHA3.hash i, fctInc = hashinc (SHA3.init i) SHA3.update SHA3.finalize }
kekkakHash i = HashFct { fctHash = Kekkak.hash i, fctInc = hashinc (Kekkak.init i) Kekkak.update Kekkak.finalize }

ripemd160Hash = HashFct { fctHash = RIPEMD160.hash, fctInc = hashinc RIPEMD160.init RIPEMD160.update RIPEMD160.finalize }
tigerHash = HashFct { fctHash = Tiger.hash, fctInc = hashinc Tiger.init Tiger.update Tiger.finalize }

skein256Hash x = HashFct { fctHash = Skein256.hash x, fctInc = hashinc (Skein256.init x) Skein256.update Skein256.finalize }
skein512Hash x = HashFct { fctHash = Skein512.hash x, fctInc = hashinc (Skein512.init x) Skein512.update Skein512.finalize }

whirlpoolHash = HashFct { fctHash = Whirlpool.hash, fctInc = hashinc Whirlpool.init Whirlpool.update Whirlpool.finalize }

expected :: [ (String, HashFct, [String]) ]
expected = [
    ("MD2", md2Hash, [
        "8350e5a3e24c153df2275c9f80692773",
        "03d85a0d629d2c442e987525319fc471",
        "6b890c9292668cdbbfda00a4ebf31f05" ]),
    ("MD4", md4Hash, [
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "1bee69a46ba811185c194762abaeae90",
        "b86e130ce7028da59e672d56ad0113df" ]),
    ("MD5", md5Hash, [
        "d41d8cd98f00b204e9800998ecf8427e",
        "9e107d9d372bb6826bd81d3542a419d6",
        "1055d3e698d289f2af8663725127bd4b" ]),
    ("SHA1", sha1Hash, [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" ]),
    ("SHA224", sha224Hash, [
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b" ]),
    ("SHA256", sha256Hash, [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" ]),
    ("SHA384", sha384Hash, [
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
        "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b" ]),
    ("SHA512", sha512Hash, [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
        "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045" ]),

    ("SHA512/224", sha512_224Hash, [
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
        "2b9d6565a7e40f780ba8ab7c8dcf41e3ed3b77997f4c55aa987eede5" ]),
    ("SHA512/256", sha512_256Hash, [
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
        "cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb" ]),
    ("RIPEMD160", ripemd160Hash, [
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
        "132072df690933835eb8b6ad0b77e7b6f14acad7" ]),
    ("Tiger", tigerHash, [
        "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
        "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075",
        "a8f04b0f7201a0d728101c9d26525b31764a3493fcd8458f" ])
    , ("Skein256-160", skein256Hash 160, [
        "ff800bed6d2044ee9d604a674e3fda50d9b24a72",
        "3265703c166aa3e0d7da070b9cf1b1a5953f0a77",
        "17b29aa1424b3ec022505bd215ff73fd2e6d1e5a" ])
    , ("Skein256-256", skein256Hash 256, [
        "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba",
        "c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe",
        "fb2f2f2deed0e1dd7ee2b91cee34e2d1c22072e1f5eaee288c35a0723eb653cd" ])
    , ("Skein512-160", skein512Hash 160, [
        "49daf1ccebb3544bc93cb5019ba91b0eea8876ee",
        "826325ee55a6dd18c3b2dbbc9c10420f5475975e",
        "7544ec7a35712ec953f02b0d0c86641cae4eb6e5" ])
    , ("Skein512-384", skein512Hash 384, [
        "dd5aaf4589dc227bd1eb7bc68771f5baeaa3586ef6c7680167a023ec8ce26980f06c4082c488b4ac9ef313f8cbe70808",
        "f814c107f3465e7c54048a5503547deddc377264f05c706b0d19db4847b354855ee52ab6a785c238c9e710d848542041",
        "e06520eeadc1d0a44fee1d2492547499c1e58526387c8b9c53905e5edb79f9840575cbf844e21b1ad1ea126dd8a8ca6f" ])
    , ("Skein512-512", skein512Hash 512, [
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
        "94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713",
        "7f81113575e4b4d3441940e87aca331e6d63d103fe5107f29cd877af0d0f5e0ea34164258c60da5190189d0872e63a96596d2ef25e709099842da71d64111e0f" ])
    , ("Skein512-896", skein512Hash 896, [
        "b95175236c83a459ce7ec6c12b761a838b22d750e765b3fdaa892201b2aa714bc3d1d887dd64028bbf177c1dd11baa09c6c4ddb598fd07d6a8c131a09fc5b958e2999a8006754b25abe3bf8492b7eabec70e52e04e5ac867df2393c573f16eee3244554f1d2b724f2c0437c62007f770",
        "3265708553e7d146e5c7bcbc97b3e9e9f5b53a5e4af53612bdd6454da4fa7b13d413184fe34ed57b6574be10e389d0ec4b1d2b1dd2c80e0257d5a76b2cd86a19a27b1bcb3cc24d911b5dc5ee74d19ad558fd85b5f024e99f56d1d3199f1f9f88ed85fab9f945f11cf9fc00e94e3ca4c7",
        "3d23d3db9be719bbd2119f8402a28f38d8225faa79d5b68b80738c64a82004aafc7a840cd6dd9bced6644fa894a3d8d7d2ee89525fd1956a2db052c4c2f8d2111c91ef46b0997540d42bcf384826af1a5ef6510077f52d0574cf2b46f1b6a5dad07ed40f3d21a13ca2d079fa602ff02d" ])
    , ("Whirlpool", whirlpoolHash, [
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35",
        "dce81fc695cfea3d7e1446509238daf89f24cc61896f2d265927daa70f2108f8902f0dfd68be085d5abb9fcd2e482c1dc24f2fabf81f40b73495cad44d7360d3"])
    , ("Kekkak-224", kekkakHash 224, [
        "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
        "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe",
        "0b27ff3b732133287f6831e2af47cf342b7ef1f3fcdee248811090cd" ])
    , ("Kekkak-256", kekkakHash 256, [
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        "ed6c07f044d7573cc53bf1276f8cba3dac497919597a45b4599c8f73e22aa334" ])
    , ("Kekkak-384", kekkakHash 384, [
        "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
        "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3",
        "1cc515e1812491058d8b8b226fd85045e746b4937a58b0111b6b7a39dd431b6295bd6b6d05e01e225586b4dab3cbb87a" ])
    , ("Kekkak-512", kekkakHash 512, [
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
        "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609",
        "10f8caabb5b179861da5e447d34b84d604e3eb81830880e1c2135ffc94580a47cb21f6243ec0053d58b1124d13af2090033659075ee718e0f111bb3f69fb24cf" ])
    , ("SHA3-224", sha3Hash 224, [
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
        "b770eb6ac3ac52bd2f9e8dc186d6b604e7c3b7ffc8bd9220b0078ced" ])
    , ("SHA3-256", sha3Hash 256, [
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        "cc80b0b13ba89613d93f02ee7ccbe72ee26c6edfe577f22e63a1380221caedbc" ])
    , ("SHA3-384", sha3Hash 384, [
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
        "e414797403c7d01ab64b41e90df4165d59b7f147e4292ba2da336acba242fd651949eb1cfff7e9012e134b40981842e1" ])
    , ("SHA3-512", sha3Hash 512, [
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
        "28e361fe8c56e617caa56c28c7c36e5c13be552b77081be82b642f08bb7ef085b9a81910fe98269386b9aacfd2349076c9506126e198f6f6ad44c12017ca77b1" ])
    ]

showHash :: B.ByteString -> String
showHash = map (toEnum.fromEnum) . hexalise . B.unpack

runhash hash v = showHash $ (fctHash hash) $ v
runhashinc hash v = showHash $ (fctInc hash) $ v

makeTestAlg (name, hash, results) = testGroup name $ concatMap maketest (zip3 is vectors results)
    where
        runtest :: ByteString -> String
        runtest v = runhash hash v

        is :: [Int]
        is = [0..]

        runtestinc :: Int -> ByteString -> String
        runtestinc i v = runhashinc hash $ splitB i v

        maketest (i, v, r) =
            [ testCase (show i ++ " one-pass") (r @=? runtest v)
            , testCase (show i ++ " inc 1") (r @=? runtestinc 1 v)
            , testCase (show i ++ " inc 2") (r @=? runtestinc 2 v)
            , testCase (show i ++ " inc 3") (r @=? runtestinc 3 v)
            , testCase (show i ++ " inc 4") (r @=? runtestinc 4 v)
            , testCase (show i ++ " inc 5") (r @=? runtestinc 5 v)
            , testCase (show i ++ " inc 9") (r @=? runtestinc 9 v)
            , testCase (show i ++ " inc 16") (r @=? runtestinc 16 v)
            ]

katTests :: [TestTree]
katTests = map makeTestAlg expected

tests = testGroup "hash"
    [ testGroup "KATs" katTests
    ]
