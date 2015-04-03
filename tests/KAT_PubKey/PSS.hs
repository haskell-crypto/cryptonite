{-# LANGUAGE OverloadedStrings #-}
module KAT_PubKey.PSS (pssTests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Crypto.PubKey.RSA
import Crypto.PubKey.MaskGenFunction
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.Hash.SHA1 as SHA1

import Test.Tasty
import Test.Tasty.HUnit

data VectorPSS = VectorPSS { message :: ByteString
                           , salt :: ByteString
                           , signature :: ByteString
                           }

rsaKeyInt = PrivateKey
    { private_pub = PublicKey
        { public_n = 0xa2ba40ee07e3b2bd2f02ce227f36a195024486e49c19cb41bbbdfbba98b22b0e577c2eeaffa20d883a76e65e394c69d4b3c05a1e8fadda27edb2a42bc000fe888b9b32c22d15add0cd76b3e7936e19955b220dd17d4ea904b1ec102b2e4de7751222aa99151024c7cb41cc5ea21d00eeb41f7c800834d2c6e06bce3bce7ea9a5
        , public_e = 0x010001
        , public_size = 128
        }
    , private_d = 0x50e2c3e38d886110288dfc68a9533e7e12e27d2aa56d2cdb3fb6efa990bcff29e1d2987fb711962860e7391b1ce01ebadb9e812d2fbdfaf25df4ae26110a6d7a26f0b810f54875e17dd5c9fb6d641761245b81e79f8c88f0e55a6dcd5f133abd35f8f4ec80adf1bf86277a582894cb6ebcd2162f1c7534f1f4947b129151b71
    , private_p = 0xd17f655bf27c8b16d35462c905cc04a26f37e2a67fa9c0ce0dced472394a0df743fe7f929e378efdb368eddff453cf007af6d948e0ade757371f8a711e278f6b
    , private_q = 0xc6d92b6fee7414d1358ce1546fb62987530b90bd15e0f14963a5e2635adb69347ec0c01b2ab1763fd8ac1a592fb22757463a982425bb97a3a437c5bf86d03f2f
    , private_dP = 0x9d0dbf83e5ce9e4b1754dcd5cd05bcb7b55f1508330ea49f14d4e889550f8256cb5f806dff34b17ada44208853577d08e4262890acf752461cea05547601bc4f
    , private_dQ = 0x1291a524c6b7c059e90e46dc83b2171eb3fa98818fd179b6c8bf6cecaa476303abf283fe05769cfc495788fe5b1ddfde9e884a3cd5e936b7e955ebf97eb563b1
    , private_qinv = 0xa63f1da38b950c9ad1c67ce0d677ec2914cd7d40062df42a67eb198a176f9742aac7c5fea14f2297662b84812c4defc49a8025ab4382286be4c03788dd01d69f
    }

rsaKey1 = PrivateKey
    { private_pub = PublicKey
        { public_n = 0xa56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137
        , public_e = 0x010001
        , public_size = 128
        }
    , private_d = 0x33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325
    , private_p = 0xe7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443
    , private_q = 0xb69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd
    , private_dP = 0x28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979
    , private_dQ = 0x1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729
    , private_qinv = 0x27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d
    }

vectorInt = VectorPSS
    { message = "\x85\x9e\xef\x2f\xd7\x8a\xca\x00\x30\x8b\xdc\x47\x11\x93\xbf\x55\xbf\x9d\x78\xdb\x8f\x8a\x67\x2b\x48\x46\x34\xf3\xc9\xc2\x6e\x64\x78\xae\x10\x26\x0f\xe0\xdd\x8c\x08\x2e\x53\xa5\x29\x3a\xf2\x17\x3c\xd5\x0c\x6d\x5d\x35\x4f\xeb\xf7\x8b\x26\x02\x1c\x25\xc0\x27\x12\xe7\x8c\xd4\x69\x4c\x9f\x46\x97\x77\xe4\x51\xe7\xf8\xe9\xe0\x4c\xd3\x73\x9c\x6b\xbf\xed\xae\x48\x7f\xb5\x56\x44\xe9\xca\x74\xff\x77\xa5\x3c\xb7\x29\x80\x2f\x6e\xd4\xa5\xff\xa8\xba\x15\x98\x90\xfc"
    , salt = "\xe3\xb5\xd5\xd0\x02\xc1\xbc\xe5\x0c\x2b\x65\xef\x88\xa1\x88\xd8\x3b\xce\x7e\x61"
    , signature = "\x8d\xaa\x62\x7d\x3d\xe7\x59\x5d\x63\x05\x6c\x7e\xc6\x59\xe5\x44\x06\xf1\x06\x10\x12\x8b\xaa\xe8\x21\xc8\xb2\xa0\xf3\x93\x6d\x54\xdc\x3b\xdc\xe4\x66\x89\xf6\xb7\x95\x1b\xb1\x8e\x84\x05\x42\x76\x97\x18\xd5\x71\x5d\x21\x0d\x85\xef\xbb\x59\x61\x92\x03\x2c\x42\xbe\x4c\x29\x97\x2c\x85\x62\x75\xeb\x6d\x5a\x45\xf0\x5f\x51\x87\x6f\xc6\x74\x3d\xed\xdd\x28\xca\xec\x9b\xb3\x0e\xa9\x9e\x02\xc3\x48\x82\x69\x60\x4f\xe4\x97\xf7\x4c\xcd\x7c\x7f\xca\x16\x71\x89\x71\x23\xcb\xd3\x0d\xef\x5d\x54\xa2\xb5\x53\x6a\xd9\x0a\x74\x7e"
    }

{-
# mHash    = Hash(M)
# salt     = random string of octets
# M'       = Padding || mHash || salt
# H        = Hash(M')
# DB       = Padding || salt 
# dbMask   = MGF(H, length(DB))
# maskedDB = DB xor dbMask (leftmost bit set to
#            zero)
# EM       = maskedDB || H || 0xbc

# mHash:
37 b6 6a e0 44 58 43 35 3d 47 ec b0 b4 fd 14 c1 
10 e6 2d 6a 

# salt:

# M':
00 00 00 00 00 00 00 00 37 b6 6a e0 44 58 43 35 
3d 47 ec b0 b4 fd 14 c1 10 e6 2d 6a e3 b5 d5 d0 
02 c1 bc e5 0c 2b 65 ef 88 a1 88 d8 3b ce 7e 61 

# H:
df 1a 89 6f 9d 8b c8 16 d9 7c d7 a2 c4 3b ad 54 
6f be 8c fe 

# DB:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 01 e3 b5 d5 d0 02 c1 bc e5 0c 
2b 65 ef 88 a1 88 d8 3b ce 7e 61 

# dbMask:
66 e4 67 2e 83 6a d1 21 ba 24 4b ed 65 76 b8 67 
d9 a4 47 c2 8a 6e 66 a5 b8 7d ee 7f bc 7e 65 af 
50 57 f8 6f ae 89 84 d9 ba 7f 96 9a d6 fe 02 a4 
d7 5f 74 45 fe fd d8 5b 6d 3a 47 7c 28 d2 4b a1 
e3 75 6f 79 2d d1 dc e8 ca 94 44 0e cb 52 79 ec 
d3 18 3a 31 1f c8 97 39 a9 66 43 13 6e 8b 0f 46 
5e 87 a4 53 5c d4 c5 9b 10 02 8d 

# maskedDB:
66 e4 67 2e 83 6a d1 21 ba 24 4b ed 65 76 b8 67 
d9 a4 47 c2 8a 6e 66 a5 b8 7d ee 7f bc 7e 65 af 
50 57 f8 6f ae 89 84 d9 ba 7f 96 9a d6 fe 02 a4 
d7 5f 74 45 fe fd d8 5b 6d 3a 47 7c 28 d2 4b a1 
e3 75 6f 79 2d d1 dc e8 ca 94 44 0e cb 52 79 ec 
d3 18 3a 31 1f c8 96 da 1c b3 93 11 af 37 ea 4a 
75 e2 4b db fd 5c 1d a0 de 7c ec 

# Encoded message EM:
66 e4 67 2e 83 6a d1 21 ba 24 4b ed 65 76 b8 67 
d9 a4 47 c2 8a 6e 66 a5 b8 7d ee 7f bc 7e 65 af 
50 57 f8 6f ae 89 84 d9 ba 7f 96 9a d6 fe 02 a4 
d7 5f 74 45 fe fd d8 5b 6d 3a 47 7c 28 d2 4b a1 
e3 75 6f 79 2d d1 dc e8 ca 94 44 0e cb 52 79 ec 
d3 18 3a 31 1f c8 96 da 1c b3 93 11 af 37 ea 4a 
75 e2 4b db fd 5c 1d a0 de 7c ec df 1a 89 6f 9d 
8b c8 16 d9 7c d7 a2 c4 3b ad 54 6f be 8c fe bc 
-}

vectorsKey1 =
    [
    -- Example 1.1
      VectorPSS
        { message = "\xcd\xc8\x7d\xa2\x23\xd7\x86\xdf\x3b\x45\xe0\xbb\xbc\x72\x13\x26\xd1\xee\x2a\xf8\x06\xcc\x31\x54\x75\xcc\x6f\x0d\x9c\x66\xe1\xb6\x23\x71\xd4\x5c\xe2\x39\x2e\x1a\xc9\x28\x44\xc3\x10\x10\x2f\x15\x6a\x0d\x8d\x52\xc1\xf4\xc4\x0b\xa3\xaa\x65\x09\x57\x86\xcb\x76\x97\x57\xa6\x56\x3b\xa9\x58\xfe\xd0\xbc\xc9\x84\xe8\xb5\x17\xa3\xd5\xf5\x15\xb2\x3b\x8a\x41\xe7\x4a\xa8\x67\x69\x3f\x90\xdf\xb0\x61\xa6\xe8\x6d\xfa\xae\xe6\x44\x72\xc0\x0e\x5f\x20\x94\x57\x29\xcb\xeb\xe7\x7f\x06\xce\x78\xe0\x8f\x40\x98\xfb\xa4\x1f\x9d\x61\x93\xc0\x31\x7e\x8b\x60\xd4\xb6\x08\x4a\xcb\x42\xd2\x9e\x38\x08\xa3\xbc\x37\x2d\x85\xe3\x31\x17\x0f\xcb\xf7\xcc\x72\xd0\xb7\x1c\x29\x66\x48\xb3\xa4\xd1\x0f\x41\x62\x95\xd0\x80\x7a\xa6\x25\xca\xb2\x74\x4f\xd9\xea\x8f\xd2\x23\xc4\x25\x37\x02\x98\x28\xbd\x16\xbe\x02\x54\x6f\x13\x0f\xd2\xe3\x3b\x93\x6d\x26\x76\xe0\x8a\xed\x1b\x73\x31\x8b\x75\x0a\x01\x67\xd0"
        , salt = "\xde\xe9\x59\xc7\xe0\x64\x11\x36\x14\x20\xff\x80\x18\x5e\xd5\x7f\x3e\x67\x76\xaf"
        , signature = "\x90\x74\x30\x8f\xb5\x98\xe9\x70\x1b\x22\x94\x38\x8e\x52\xf9\x71\xfa\xac\x2b\x60\xa5\x14\x5a\xf1\x85\xdf\x52\x87\xb5\xed\x28\x87\xe5\x7c\xe7\xfd\x44\xdc\x86\x34\xe4\x07\xc8\xe0\xe4\x36\x0b\xc2\x26\xf3\xec\x22\x7f\x9d\x9e\x54\x63\x8e\x8d\x31\xf5\x05\x12\x15\xdf\x6e\xbb\x9c\x2f\x95\x79\xaa\x77\x59\x8a\x38\xf9\x14\xb5\xb9\xc1\xbd\x83\xc4\xe2\xf9\xf3\x82\xa0\xd0\xaa\x35\x42\xff\xee\x65\x98\x4a\x60\x1b\xc6\x9e\xb2\x8d\xeb\x27\xdc\xa1\x2c\x82\xc2\xd4\xc3\xf6\x6c\xd5\x00\xf1\xff\x2b\x99\x4d\x8a\x4e\x30\xcb\xb3\x3c"
        }
    -- Example 1.2
    , VectorPSS
        { message = "\x85\x13\x84\xcd\xfe\x81\x9c\x22\xed\x6c\x4c\xcb\x30\xda\xeb\x5c\xf0\x59\xbc\x8e\x11\x66\xb7\xe3\x53\x0c\x4c\x23\x3e\x2b\x5f\x8f\x71\xa1\xcc\xa5\x82\xd4\x3e\xcc\x72\xb1\xbc\xa1\x6d\xfc\x70\x13\x22\x6b\x9e"
        , salt = "\xef\x28\x69\xfa\x40\xc3\x46\xcb\x18\x3d\xab\x3d\x7b\xff\xc9\x8f\xd5\x6d\xf4\x2d"
        , signature = "\x3e\xf7\xf4\x6e\x83\x1b\xf9\x2b\x32\x27\x41\x42\xa5\x85\xff\xce\xfb\xdc\xa7\xb3\x2a\xe9\x0d\x10\xfb\x0f\x0c\x72\x99\x84\xf0\x4e\xf2\x9a\x9d\xf0\x78\x07\x75\xce\x43\x73\x9b\x97\x83\x83\x90\xdb\x0a\x55\x05\xe6\x3d\xe9\x27\x02\x8d\x9d\x29\xb2\x19\xca\x2c\x45\x17\x83\x25\x58\xa5\x5d\x69\x4a\x6d\x25\xb9\xda\xb6\x60\x03\xc4\xcc\xcd\x90\x78\x02\x19\x3b\xe5\x17\x0d\x26\x14\x7d\x37\xb9\x35\x90\x24\x1b\xe5\x1c\x25\x05\x5f\x47\xef\x62\x75\x2c\xfb\xe2\x14\x18\xfa\xfe\x98\xc2\x2c\x4d\x4d\x47\x72\x4f\xdb\x56\x69\xe8\x43"
        }
    -- Example 1.3
    , VectorPSS
        { message = "\xa4\xb1\x59\x94\x17\x61\xc4\x0c\x6a\x82\xf2\xb8\x0d\x1b\x94\xf5\xaa\x26\x54\xfd\x17\xe1\x2d\x58\x88\x64\x67\x9b\x54\xcd\x04\xef\x8b\xd0\x30\x12\xbe\x8d\xc3\x7f\x4b\x83\xaf\x79\x63\xfa\xff\x0d\xfa\x22\x54\x77\x43\x7c\x48\x01\x7f\xf2\xbe\x81\x91\xcf\x39\x55\xfc\x07\x35\x6e\xab\x3f\x32\x2f\x7f\x62\x0e\x21\xd2\x54\xe5\xdb\x43\x24\x27\x9f\xe0\x67\xe0\x91\x0e\x2e\x81\xca\x2c\xab\x31\xc7\x45\xe6\x7a\x54\x05\x8e\xb5\x0d\x99\x3c\xdb\x9e\xd0\xb4\xd0\x29\xc0\x6d\x21\xa9\x4c\xa6\x61\xc3\xce\x27\xfa\xe1\xd6\xcb\x20\xf4\x56\x4d\x66\xce\x47\x67\x58\x3d\x0e\x5f\x06\x02\x15\xb5\x90\x17\xbe\x85\xea\x84\x89\x39\x12\x7b\xd8\xc9\xc4\xd4\x7b\x51\x05\x6c\x03\x1c\xf3\x36\xf1\x7c\x99\x80\xf3\xb8\xf5\xb9\xb6\x87\x8e\x8b\x79\x7a\xa4\x3b\x88\x26\x84\x33\x3e\x17\x89\x3f\xe9\xca\xa6\xaa\x29\x9f\x7e\xd1\xa1\x8e\xe2\xc5\x48\x64\xb7\xb2\xb9\x9b\x72\x61\x8f\xb0\x25\x74\xd1\x39\xef\x50\xf0\x19\xc9\xee\xf4\x16\x97\x13\x38\xe7\xd4\x70"
        , salt = "\x71\x0b\x9c\x47\x47\xd8\x00\xd4\xde\x87\xf1\x2a\xfd\xce\x6d\xf1\x81\x07\xcc\x77"
        , signature = "\x66\x60\x26\xfb\xa7\x1b\xd3\xe7\xcf\x13\x15\x7c\xc2\xc5\x1a\x8e\x4a\xa6\x84\xaf\x97\x78\xf9\x18\x49\xf3\x43\x35\xd1\x41\xc0\x01\x54\xc4\x19\x76\x21\xf9\x62\x4a\x67\x5b\x5a\xbc\x22\xee\x7d\x5b\xaa\xff\xaa\xe1\xc9\xba\xca\x2c\xc3\x73\xb3\xf3\x3e\x78\xe6\x14\x3c\x39\x5a\x91\xaa\x7f\xac\xa6\x64\xeb\x73\x3a\xfd\x14\xd8\x82\x72\x59\xd9\x9a\x75\x50\xfa\xca\x50\x1e\xf2\xb0\x4e\x33\xc2\x3a\xa5\x1f\x4b\x9e\x82\x82\xef\xdb\x72\x8c\xc0\xab\x09\x40\x5a\x91\x60\x7c\x63\x69\x96\x1b\xc8\x27\x0d\x2d\x4f\x39\xfc\xe6\x12\xb1"
        }
    -- Example 1.4
    , VectorPSS
        { message = "\xbc\x65\x67\x47\xfa\x9e\xaf\xb3\xf0"
        , salt = "\x05\x6f\x00\x98\x5d\xe1\x4d\x8e\xf5\xce\xa9\xe8\x2f\x8c\x27\xbe\xf7\x20\x33\x5e"
        , signature = "\x46\x09\x79\x3b\x23\xe9\xd0\x93\x62\xdc\x21\xbb\x47\xda\x0b\x4f\x3a\x76\x22\x64\x9a\x47\xd4\x64\x01\x9b\x9a\xea\xfe\x53\x35\x9c\x17\x8c\x91\xcd\x58\xba\x6b\xcb\x78\xbe\x03\x46\xa7\xbc\x63\x7f\x4b\x87\x3d\x4b\xab\x38\xee\x66\x1f\x19\x96\x34\xc5\x47\xa1\xad\x84\x42\xe0\x3d\xa0\x15\xb1\x36\xe5\x43\xf7\xab\x07\xc0\xc1\x3e\x42\x25\xb8\xde\x8c\xce\x25\xd4\xf6\xeb\x84\x00\xf8\x1f\x7e\x18\x33\xb7\xee\x6e\x33\x4d\x37\x09\x64\xca\x79\xfd\xb8\x72\xb4\xd7\x52\x23\xb5\xee\xb0\x81\x01\x59\x1f\xb5\x32\xd1\x55\xa6\xde\x87"
        }
    -- Example 1.5
    , VectorPSS
        { message = "\xb4\x55\x81\x54\x7e\x54\x27\x77\x0c\x76\x8e\x8b\x82\xb7\x55\x64\xe0\xea\x4e\x9c\x32\x59\x4d\x6b\xff\x70\x65\x44\xde\x0a\x87\x76\xc7\xa8\x0b\x45\x76\x55\x0e\xee\x1b\x2a\xca\xbc\x7e\x8b\x7d\x3e\xf7\xbb\x5b\x03\xe4\x62\xc1\x10\x47\xea\xdd\x00\x62\x9a\xe5\x75\x48\x0a\xc1\x47\x0f\xe0\x46\xf1\x3a\x2b\xf5\xaf\x17\x92\x1d\xc4\xb0\xaa\x8b\x02\xbe\xe6\x33\x49\x11\x65\x1d\x7f\x85\x25\xd1\x0f\x32\xb5\x1d\x33\xbe\x52\x0d\x3d\xdf\x5a\x70\x99\x55\xa3\xdf\xe7\x82\x83\xb9\xe0\xab\x54\x04\x6d\x15\x0c\x17\x7f\x03\x7f\xdc\xcc\x5b\xe4\xea\x5f\x68\xb5\xe5\xa3\x8c\x9d\x7e\xdc\xcc\xc4\x97\x5f\x45\x5a\x69\x09\xb4"
        , salt = "\x80\xe7\x0f\xf8\x6a\x08\xde\x3e\xc6\x09\x72\xb3\x9b\x4f\xbf\xdc\xea\x67\xae\x8e"
        , signature = "\x1d\x2a\xad\x22\x1c\xa4\xd3\x1d\xdf\x13\x50\x92\x39\x01\x93\x98\xe3\xd1\x4b\x32\xdc\x34\xdc\x5a\xf4\xae\xae\xa3\xc0\x95\xaf\x73\x47\x9c\xf0\xa4\x5e\x56\x29\x63\x5a\x53\xa0\x18\x37\x76\x15\xb1\x6c\xb9\xb1\x3b\x3e\x09\xd6\x71\xeb\x71\xe3\x87\xb8\x54\x5c\x59\x60\xda\x5a\x64\x77\x6e\x76\x8e\x82\xb2\xc9\x35\x83\xbf\x10\x4c\x3f\xdb\x23\x51\x2b\x7b\x4e\x89\xf6\x33\xdd\x00\x63\xa5\x30\xdb\x45\x24\xb0\x1c\x3f\x38\x4c\x09\x31\x0e\x31\x5a\x79\xdc\xd3\xd6\x84\x02\x2a\x7f\x31\xc8\x65\xa6\x64\xe3\x16\x97\x8b\x75\x9f\xad"
        }
    -- Example 1.6
    , VectorPSS
        { message = "\x10\xaa\xe9\xa0\xab\x0b\x59\x5d\x08\x41\x20\x7b\x70\x0d\x48\xd7\x5f\xae\xdd\xe3\xb7\x75\xcd\x6b\x4c\xc8\x8a\xe0\x6e\x46\x94\xec\x74\xba\x18\xf8\x52\x0d\x4f\x5e\xa6\x9c\xbb\xe7\xcc\x2b\xeb\xa4\x3e\xfd\xc1\x02\x15\xac\x4e\xb3\x2d\xc3\x02\xa1\xf5\x3d\xc6\xc4\x35\x22\x67\xe7\x93\x6c\xfe\xbf\x7c\x8d\x67\x03\x57\x84\xa3\x90\x9f\xa8\x59\xc7\xb7\xb5\x9b\x8e\x39\xc5\xc2\x34\x9f\x18\x86\xb7\x05\xa3\x02\x67\xd4\x02\xf7\x48\x6a\xb4\xf5\x8c\xad\x5d\x69\xad\xb1\x7a\xb8\xcd\x0c\xe1\xca\xf5\x02\x5a\xf4\xae\x24\xb1\xfb\x87\x94\xc6\x07\x0c\xc0\x9a\x51\xe2\xf9\x91\x13\x11\xe3\x87\x7d\x00\x44\xc7\x1c\x57\xa9\x93\x39\x50\x08\x80\x6b\x72\x3a\xc3\x83\x73\xd3\x95\x48\x18\x18\x52\x8c\x1e\x70\x53\x73\x92\x82\x05\x35\x29\x51\x0e\x93\x5c\xd0\xfa\x77\xb8\xfa\x53\xcc\x2d\x47\x4b\xd4\xfb\x3c\xc5\xc6\x72\xd6\xff\xdc\x90\xa0\x0f\x98\x48\x71\x2c\x4b\xcf\xe4\x6c\x60\x57\x36\x59\xb1\x1e\x64\x57\xe8\x61\xf0\xf6\x04\xb6\x13\x8d\x14\x4f\x8c\xe4\xe2\xda\x73"
        , salt = "\xa8\xab\x69\xdd\x80\x1f\x00\x74\xc2\xa1\xfc\x60\x64\x98\x36\xc6\x16\xd9\x96\x81"
        , signature = "\x2a\x34\xf6\x12\x5e\x1f\x6b\x0b\xf9\x71\xe8\x4f\xbd\x41\xc6\x32\xbe\x8f\x2c\x2a\xce\x7d\xe8\xb6\x92\x6e\x31\xff\x93\xe9\xaf\x98\x7f\xbc\x06\xe5\x1e\x9b\xe1\x4f\x51\x98\xf9\x1f\x3f\x95\x3b\xd6\x7d\xa6\x0a\x9d\xf5\x97\x64\xc3\xdc\x0f\xe0\x8e\x1c\xbe\xf0\xb7\x5f\x86\x8d\x10\xad\x3f\xba\x74\x9f\xef\x59\xfb\x6d\xac\x46\xa0\xd6\xe5\x04\x36\x93\x31\x58\x6f\x58\xe4\x62\x8f\x39\xaa\x27\x89\x82\x54\x3b\xc0\xee\xb5\x37\xdc\x61\x95\x80\x19\xb3\x94\xfb\x27\x3f\x21\x58\x58\xa0\xa0\x1a\xc4\xd6\x50\xb9\x55\xc6\x7f\x4c\x58"
        }
    ]

{-
# ===================================
# Example 10: A 2048-bit RSA Key Pair
# ===================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
a5 dd 86 7a c4 cb 02 f9 0b 94 57 d4 8c 14 a7 70 
ef 99 1c 56 c3 9c 0e c6 5f d1 1a fa 89 37 ce a5 
7b 9b e7 ac 73 b4 5c 00 17 61 5b 82 d6 22 e3 18 
75 3b 60 27 c0 fd 15 7b e1 2f 80 90 fe e2 a7 ad 
cd 0e ef 75 9f 88 ba 49 97 c7 a4 2d 58 c9 aa 12 
cb 99 ae 00 1f e5 21 c1 3b b5 43 14 45 a8 d5 ae 
4f 5e 4c 7e 94 8a c2 27 d3 60 40 71 f2 0e 57 7e 
90 5f be b1 5d fa f0 6d 1d e5 ae 62 53 d6 3a 6a 
21 20 b3 1a 5d a5 da bc 95 50 60 0e 20 f2 7d 37 
39 e2 62 79 25 fe a3 cc 50 9f 21 df f0 4e 6e ea 
45 49 c5 40 d6 80 9f f9 30 7e ed e9 1f ff 58 73 
3d 83 85 a2 37 d6 d3 70 5a 33 e3 91 90 09 92 07 
0d f7 ad f1 35 7c f7 e3 70 0c e3 66 7d e8 3f 17 
b8 df 17 78 db 38 1d ce 09 cb 4a d0 58 a5 11 00 
1a 73 81 98 ee 27 cf 55 a1 3b 75 45 39 90 65 82 
ec 8b 17 4b d5 8d 5d 1f 3d 76 7c 61 37 21 ae 05 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
2d 2f f5 67 b3 fe 74 e0 61 91 b7 fd ed 6d e1 12 
29 0c 67 06 92 43 0d 59 69 18 40 47 da 23 4c 96 
93 de ed 16 73 ed 42 95 39 c9 69 d3 72 c0 4d 6b 
47 e0 f5 b8 ce e0 84 3e 5c 22 83 5d bd 3b 05 a0 
99 79 84 ae 60 58 b1 1b c4 90 7c bf 67 ed 84 fa 
9a e2 52 df b0 d0 cd 49 e6 18 e3 5d fd fe 59 bc 
a3 dd d6 6c 33 ce bb c7 7a d4 41 aa 69 5e 13 e3 
24 b5 18 f0 1c 60 f5 a8 5c 99 4a d1 79 f2 a6 b5 
fb e9 34 02 b1 17 67 be 01 bf 07 34 44 d6 ba 1d 
d2 bc a5 bd 07 4d 4a 5f ae 35 31 ad 13 03 d8 4b 
30 d8 97 31 8c bb ba 04 e0 3c 2e 66 de 6d 91 f8 
2f 96 ea 1d 4b b5 4a 5a ae 10 2d 59 46 57 f5 c9 
78 95 53 51 2b 29 6d ea 29 d8 02 31 96 35 7e 3e 
3a 6e 95 8f 39 e3 c2 34 40 38 ea 60 4b 31 ed c6 
f0 f7 ff 6e 71 81 a5 7c 92 82 6a 26 8f 86 76 8e 
96 f8 78 56 2f c7 1d 85 d6 9e 44 86 12 f7 04 8f 

# Prime p: 
cf d5 02 83 fe ee b9 7f 6f 08 d7 3c bc 7b 38 36 
f8 2b bc d4 99 47 9f 5e 6f 76 fd fc b8 b3 8c 4f 
71 dc 9e 88 bd 6a 6f 76 37 1a fd 65 d2 af 18 62 
b3 2a fb 34 a9 5f 71 b8 b1 32 04 3f fe be 3a 95 
2b af 75 92 44 81 48 c0 3f 9c 69 b1 d6 8e 4c e5 
cf 32 c8 6b af 46 fe d3 01 ca 1a b4 03 06 9b 32 
f4 56 b9 1f 71 89 8a b0 81 cd 8c 42 52 ef 52 71 
91 5c 97 94 b8 f2 95 85 1d a7 51 0f 99 cb 73 eb 

# Prime q: 
cc 4e 90 d2 a1 b3 a0 65 d3 b2 d1 f5 a8 fc e3 1b 
54 44 75 66 4e ab 56 1d 29 71 b9 9f b7 be f8 44 
e8 ec 1f 36 0b 8c 2a c8 35 96 92 97 1e a6 a3 8f 
72 3f cc 21 1f 5d bc b1 77 a0 fd ac 51 64 a1 d4 
ff 7f bb 4e 82 99 86 35 3c b9 83 65 9a 14 8c dd 
42 0c 7d 31 ba 38 22 ea 90 a3 2b e4 6c 03 0e 8c 
17 e1 fa 0a d3 78 59 e0 6b 0a a6 fa 3b 21 6d 9c 
be 6c 0e 22 33 97 69 c0 a6 15 91 3e 5d a7 19 cf 

# p's CRT exponent dP: 
1c 2d 1f c3 2f 6b c4 00 4f d8 5d fd e0 fb bf 9a 
4c 38 f9 c7 c4 e4 1d ea 1a a8 82 34 a2 01 cd 92 
f3 b7 da 52 65 83 a9 8a d8 5b b3 60 fb 98 3b 71 
1e 23 44 9d 56 1d 17 78 d7 a5 15 48 6b cb f4 7b 
46 c9 e9 e1 a3 a1 f7 70 00 ef be b0 9a 8a fe 47 
e5 b8 57 cd a9 9c b1 6d 7f ff 9b 71 2e 3b d6 0c 
a9 6d 9c 79 73 d6 16 d4 69 34 a9 c0 50 28 1c 00 
43 99 ce ff 1d b7 dd a7 87 66 a8 a9 b9 cb 08 73 

# q's CRT exponent dQ: 
cb 3b 3c 04 ca a5 8c 60 be 7d 9b 2d eb b3 e3 96 
43 f4 f5 73 97 be 08 23 6a 1e 9e af aa 70 65 36 
e7 1c 3a cf e0 1c c6 51 f2 3c 9e 05 85 8f ee 13 
bb 6a 8a fc 47 df 4e dc 9a 4b a3 0b ce cb 73 d0 
15 78 52 32 7e e7 89 01 5c 2e 8d ee 7b 9f 05 a0 
f3 1a c9 4e b6 17 31 64 74 0c 5c 95 14 7c d5 f3 
b5 ae 2c b4 a8 37 87 f0 1d 8a b3 1f 27 c2 d0 ee 
a2 dd 8a 11 ab 90 6a ba 20 7c 43 c6 ee 12 53 31 

# CRT coefficient qInv: 
12 f6 b2 cf 13 74 a7 36 fa d0 56 16 05 0f 96 ab 
4b 61 d1 17 7c 7f 9d 52 5a 29 f3 d1 80 e7 76 67 
e9 9d 99 ab f0 52 5d 07 58 66 0f 37 52 65 5b 0f 
25 b8 df 84 31 d9 a8 ff 77 c1 6c 12 a0 a5 12 2a 
9f 0b f7 cf d5 a2 66 a3 5c 15 9f 99 12 08 b9 03 
16 ff 44 4f 3e 0b 6b d0 e9 3b 8a 7a 24 48 e9 57 
e3 dd a6 cf cf 22 66 b1 06 01 3a c4 68 08 d3 b3 
88 7b 3b 00 34 4b aa c9 53 0b 4c e7 08 fc 32 b6 

# ---------------------------------
# RSASSA-PSS Signature Example 10.1
# ---------------------------------

# Message to be signed:
88 31 77 e5 12 6b 9b e2 d9 a9 68 03 27 d5 37 0c 
6f 26 86 1f 58 20 c4 3d a6 7a 3a d6 09 

# Salt:
04 e2 15 ee 6f f9 34 b9 da 70 d7 73 0c 87 34 ab 
fc ec de 89 

# Signature:
82 c2 b1 60 09 3b 8a a3 c0 f7 52 2b 19 f8 73 54 
06 6c 77 84 7a bf 2a 9f ce 54 2d 0e 84 e9 20 c5 
af b4 9f fd fd ac e1 65 60 ee 94 a1 36 96 01 14 
8e ba d7 a0 e1 51 cf 16 33 17 91 a5 72 7d 05 f2 
1e 74 e7 eb 81 14 40 20 69 35 d7 44 76 5a 15 e7 
9f 01 5c b6 6c 53 2c 87 a6 a0 59 61 c8 bf ad 74 
1a 9a 66 57 02 28 94 39 3e 72 23 73 97 96 c0 2a 
77 45 5d 0f 55 5b 0e c0 1d df 25 9b 62 07 fd 0f 
d5 76 14 ce f1 a5 57 3b aa ff 4e c0 00 69 95 16 
59 b8 5f 24 30 0a 25 16 0c a8 52 2d c6 e6 72 7e 
57 d0 19 d7 e6 36 29 b8 fe 5e 89 e2 5c c1 5b eb 
3a 64 75 77 55 92 99 28 0b 9b 28 f7 9b 04 09 00 
0b e2 5b bd 96 40 8b a3 b4 3c c4 86 18 4d d1 c8 
e6 25 53 fa 1a f4 04 0f 60 66 3d e7 f5 e4 9c 04 
38 8e 25 7f 1c e8 9c 95 da b4 8a 31 5d 9b 66 b1 
b7 62 82 33 87 6f f2 38 52 30 d0 70 d0 7e 16 66 

# ---------------------------------
# RSASSA-PSS Signature Example 10.2
# ---------------------------------

# Message to be signed:
dd 67 0a 01 46 58 68 ad c9 3f 26 13 19 57 a5 0c 
52 fb 77 7c db aa 30 89 2c 9e 12 36 11 64 ec 13 
97 9d 43 04 81 18 e4 44 5d b8 7b ee 58 dd 98 7b 
34 25 d0 20 71 d8 db ae 80 70 8b 03 9d bb 64 db 
d1 de 56 57 d9 fe d0 c1 18 a5 41 43 74 2e 0f f3 
c8 7f 74 e4 58 57 64 7a f3 f7 9e b0 a1 4c 9d 75 
ea 9a 1a 04 b7 cf 47 8a 89 7a 70 8f d9 88 f4 8e 
80 1e db 0b 70 39 df 8c 23 bb 3c 56 f4 e8 21 ac 

# Salt:
8b 2b dd 4b 40 fa f5 45 c7 78 dd f9 bc 1a 49 cb 
57 f9 b7 1b 

# Signature:
14 ae 35 d9 dd 06 ba 92 f7 f3 b8 97 97 8a ed 7c 
d4 bf 5f f0 b5 85 a4 0b d4 6c e1 b4 2c d2 70 30 
53 bb 90 44 d6 4e 81 3d 8f 96 db 2d d7 00 7d 10 
11 8f 6f 8f 84 96 09 7a d7 5e 1f f6 92 34 1b 28 
92 ad 55 a6 33 a1 c5 5e 7f 0a 0a d5 9a 0e 20 3a 
5b 82 78 ae c5 4d d8 62 2e 28 31 d8 71 74 f8 ca 
ff 43 ee 6c 46 44 53 45 d8 4a 59 65 9b fb 92 ec 
d4 c8 18 66 86 95 f3 47 06 f6 68 28 a8 99 59 63 
7f 2b f3 e3 25 1c 24 bd ba 4d 4b 76 49 da 00 22 
21 8b 11 9c 84 e7 9a 65 27 ec 5b 8a 5f 86 1c 15 
99 52 e2 3e c0 5e 1e 71 73 46 fa ef e8 b1 68 68 
25 bd 2b 26 2f b2 53 10 66 c0 de 09 ac de 2e 42 
31 69 07 28 b5 d8 5e 11 5a 2f 6b 92 b7 9c 25 ab 
c9 bd 93 99 ff 8b cf 82 5a 52 ea 1f 56 ea 76 dd 
26 f4 3b aa fa 18 bf a9 2a 50 4c bd 35 69 9e 26 
d1 dc c5 a2 88 73 85 f3 c6 32 32 f0 6f 32 44 c3 

# ---------------------------------
# RSASSA-PSS Signature Example 10.3
# ---------------------------------

# Message to be signed:
48 b2 b6 a5 7a 63 c8 4c ea 85 9d 65 c6 68 28 4b 
08 d9 6b dc aa be 25 2d b0 e4 a9 6c b1 ba c6 01 
93 41 db 6f be fb 8d 10 6b 0e 90 ed a6 bc c6 c6 
26 2f 37 e7 ea 9c 7e 5d 22 6b d7 df 85 ec 5e 71 
ef ff 2f 54 c5 db 57 7f f7 29 ff 91 b8 42 49 1d 
e2 74 1d 0c 63 16 07 df 58 6b 90 5b 23 b9 1a f1 
3d a1 23 04 bf 83 ec a8 a7 3e 87 1f f9 db 

# Salt:
4e 96 fc 1b 39 8f 92 b4 46 71 01 0c 0d c3 ef d6 
e2 0c 2d 73 

# Signature:
6e 3e 4d 7b 6b 15 d2 fb 46 01 3b 89 00 aa 5b bb 
39 39 cf 2c 09 57 17 98 70 42 02 6e e6 2c 74 c5 
4c ff d5 d7 d5 7e fb bf 95 0a 0f 5c 57 4f a0 9d 
3f c1 c9 f5 13 b0 5b 4f f5 0d d8 df 7e df a2 01 
02 85 4c 35 e5 92 18 01 19 a7 0c e5 b0 85 18 2a 
a0 2d 9e a2 aa 90 d1 df 03 f2 da ae 88 5b a2 f5 
d0 5a fd ac 97 47 6f 06 b9 3b 5b c9 4a 1a 80 aa 
91 16 c4 d6 15 f3 33 b0 98 89 2b 25 ff ac e2 66 
f5 db 5a 5a 3b cc 10 a8 24 ed 55 aa d3 5b 72 78 
34 fb 8c 07 da 28 fc f4 16 a5 d9 b2 22 4f 1f 8b 
44 2b 36 f9 1e 45 6f de a2 d7 cf e3 36 72 68 de 
03 07 a4 c7 4e 92 41 59 ed 33 39 3d 5e 06 55 53 
1c 77 32 7b 89 82 1b de df 88 01 61 c7 8c d4 19 
6b 54 19 f7 ac c3 f1 3e 5e bf 16 1b 6e 7c 67 24 
71 6c a3 3b 85 c2 e2 56 40 19 2a c2 85 96 51 d5 
0b de 7e b9 76 e5 1c ec 82 8b 98 b6 56 3b 86 bb 

# ---------------------------------
# RSASSA-PSS Signature Example 10.4
# ---------------------------------

# Message to be signed:
0b 87 77 c7 f8 39 ba f0 a6 4b bb db c5 ce 79 75 
5c 57 a2 05 b8 45 c1 74 e2 d2 e9 05 46 a0 89 c4 
e6 ec 8a df fa 23 a7 ea 97 ba e6 b6 5d 78 2b 82 
db 5d 2b 5a 56 d2 2a 29 a0 5e 7c 44 33 e2 b8 2a 
62 1a bb a9 0a dd 05 ce 39 3f c4 8a 84 05 42 45 
1a 

# Salt:
c7 cd 69 8d 84 b6 51 28 d8 83 5e 3a 8b 1e b0 e0 
1c b5 41 ec 

# Signature:
34 04 7f f9 6c 4d c0 dc 90 b2 d4 ff 59 a1 a3 61 
a4 75 4b 25 5d 2e e0 af 7d 8b f8 7c 9b c9 e7 dd 
ee de 33 93 4c 63 ca 1c 0e 3d 26 2c b1 45 ef 93 
2a 1f 2c 0a 99 7a a6 a3 4f 8e ae e7 47 7d 82 cc 
f0 90 95 a6 b8 ac ad 38 d4 ee c9 fb 7e ab 7a d0 
2d a1 d1 1d 8e 54 c1 82 5e 55 bf 58 c2 a2 32 34 
b9 02 be 12 4f 9e 90 38 a8 f6 8f a4 5d ab 72 f6 
6e 09 45 bf 1d 8b ac c9 04 4c 6f 07 09 8c 9f ce 
c5 8a 3a ab 10 0c 80 51 78 15 5f 03 0a 12 4c 45 
0e 5a cb da 47 d0 e4 f1 0b 80 a2 3f 80 3e 77 4d 
02 3b 00 15 c2 0b 9f 9b be 7c 91 29 63 38 d5 ec 
b4 71 ca fb 03 20 07 b6 7a 60 be 5f 69 50 4a 9f 
01 ab b3 cb 46 7b 26 0e 2b ce 86 0b e8 d9 5b f9 
2c 0c 8e 14 96 ed 1e 52 85 93 a4 ab b6 df 46 2d 
de 8a 09 68 df fe 46 83 11 68 57 a2 32 f5 eb f6 
c8 5b e2 38 74 5a d0 f3 8f 76 7a 5f db f4 86 fb 

# ---------------------------------
# RSASSA-PSS Signature Example 10.5
# ---------------------------------

# Message to be signed:
f1 03 6e 00 8e 71 e9 64 da dc 92 19 ed 30 e1 7f 
06 b4 b6 8a 95 5c 16 b3 12 b1 ed df 02 8b 74 97 
6b ed 6b 3f 6a 63 d4 e7 78 59 24 3c 9c cc dc 98 
01 65 23 ab b0 24 83 b3 55 91 c3 3a ad 81 21 3b 
b7 c7 bb 1a 47 0a ab c1 0d 44 25 6c 4d 45 59 d9 
16 

# Salt:
ef a8 bf f9 62 12 b2 f4 a3 f3 71 a1 0d 57 41 52 
65 5f 5d fb 

# Signature:
7e 09 35 ea 18 f4 d6 c1 d1 7c e8 2e b2 b3 83 6c 
55 b3 84 58 9c e1 9d fe 74 33 63 ac 99 48 d1 f3 
46 b7 bf dd fe 92 ef d7 8a db 21 fa ef c8 9a de 
42 b1 0f 37 40 03 fe 12 2e 67 42 9a 1c b8 cb d1 
f8 d9 01 45 64 c4 4d 12 01 16 f4 99 0f 1a 6e 38 
77 4c 19 4b d1 b8 21 32 86 b0 77 b0 49 9d 2e 7b 
3f 43 4a b1 22 89 c5 56 68 4d ee d7 81 31 93 4b 
b3 dd 65 37 23 6f 7c 6f 3d cb 09 d4 76 be 07 72 
1e 37 e1 ce ed 9b 2f 7b 40 68 87 bd 53 15 73 05 
e1 c8 b4 f8 4d 73 3b c1 e1 86 fe 06 cc 59 b6 ed 
b8 f4 bd 7f fe fd f4 f7 ba 9c fb 9d 57 06 89 b5 
a1 a4 10 9a 74 6a 69 08 93 db 37 99 25 5a 0c b9 
21 5d 2d 1c d4 90 59 0e 95 2e 8c 87 86 aa 00 11 
26 52 52 47 0c 04 1d fb c3 ee c7 c3 cb f7 1c 24 
86 9d 11 5c 0c b4 a9 56 f5 6d 53 0b 80 ab 58 9a 
cf ef c6 90 75 1d df 36 e8 d3 83 f8 3c ed d2 cc 

# ---------------------------------
# RSASSA-PSS Signature Example 10.6
# ---------------------------------

# Message to be signed:
25 f1 08 95 a8 77 16 c1 37 45 0b b9 51 9d fa a1 
f2 07 fa a9 42 ea 88 ab f7 1e 9c 17 98 00 85 b5 
55 ae ba b7 62 64 ae 2a 3a b9 3c 2d 12 98 11 91 
dd ac 6f b5 94 9e b3 6a ee 3c 5d a9 40 f0 07 52 
c9 16 d9 46 08 fa 7d 97 ba 6a 29 15 b6 88 f2 03 
23 d4 e9 d9 68 01 d8 9a 72 ab 58 92 dc 21 17 c0 
74 34 fc f9 72 e0 58 cf 8c 41 ca 4b 4f f5 54 f7 
d5 06 8a d3 15 5f ce d0 f3 12 5b c0 4f 91 93 37 
8a 8f 5c 4c 3b 8c b4 dd 6d 1c c6 9d 30 ec ca 6e 
aa 51 e3 6a 05 73 0e 9e 34 2e 85 5b af 09 9d ef 
b8 af d7 

# Salt:
ad 8b 15 23 70 36 46 22 4b 66 0b 55 08 85 91 7c 
a2 d1 df 28 

# Signature:
6d 3b 5b 87 f6 7e a6 57 af 21 f7 54 41 97 7d 21 
80 f9 1b 2c 5f 69 2d e8 29 55 69 6a 68 67 30 d9 
b9 77 8d 97 07 58 cc b2 60 71 c2 20 9f fb d6 12 
5b e2 e9 6e a8 1b 67 cb 9b 93 08 23 9f da 17 f7 
b2 b6 4e cd a0 96 b6 b9 35 64 0a 5a 1c b4 2a 91 
55 b1 c9 ef 7a 63 3a 02 c5 9f 0d 6e e5 9b 85 2c 
43 b3 50 29 e7 3c 94 0f f0 41 0e 8f 11 4e ed 46 
bb d0 fa e1 65 e4 2b e2 52 8a 40 1c 3b 28 fd 81 
8e f3 23 2d ca 9f 4d 2a 0f 51 66 ec 59 c4 23 96 
d6 c1 1d bc 12 15 a5 6f a1 71 69 db 95 75 34 3e 
f3 4f 9d e3 2a 49 cd c3 17 49 22 f2 29 c2 3e 18 
e4 5d f9 35 31 19 ec 43 19 ce dc e7 a1 7c 64 08 
8c 1f 6f 52 be 29 63 41 00 b3 91 9d 38 f3 d1 ed 
94 e6 89 1e 66 a7 3b 8f b8 49 f5 87 4d f5 94 59 
e2 98 c7 bb ce 2e ee 78 2a 19 5a a6 6f e2 d0 73 
2b 25 e5 95 f5 7d 3e 06 1b 1f c3 e4 06 3b f9 8f 

-}

doSignTest key (i, vector) = testCase (show i) (Right (signature vector) @=? actual)
    where actual = PSS.signWithSalt (salt vector) Nothing PSS.defaultPSSParamsSHA1 key (message vector)

doVerifyTest key (i, vector) = testCase (show i) (True @=? actual)
    where actual = PSS.verify PSS.defaultPSSParamsSHA1 (private_pub key) (message vector) (signature vector)

pssTests = testGroup "RSA-PSS"
    [ testGroup "signature internal"
        [ doSignTest rsaKeyInt (0, vectorInt) ]
    , testGroup "verify internal"
        [ doVerifyTest rsaKeyInt (0, vectorInt) ]
    , testGroup "signature key 1024" $ map (doSignTest rsaKey1) (zip [0..] vectorsKey1)
    , testGroup "verify key 1024" $ map (doVerifyTest rsaKey1) (zip [0..] vectorsKey1)
    ]
