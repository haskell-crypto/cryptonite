-- |
-- Module      : Data.ByteArray.Methods
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
{-# LANGUAGE BangPatterns #-}
module Data.ByteArray.Methods
    ( alloc
    , allocAndFreeze
    , create
    , unsafeCreate
    , pack
    , unpack
    , empty
    , replicate
    , zero
    , copy
    , take
    , convert
    , convertHex
    , copyRet
    , copyAndFreeze
    , split
    , xor
    , index
    , eq
    , constEq
    , append
    , concat
    , toW64BE
    , toW64LE
    , mapAsWord64
    , mapAsWord128
    ) where

import           Data.Memory.Internal.Compat
import           Data.Memory.Internal.Imports hiding (empty)
import           Data.ByteArray.Types
import           Data.Memory.Endian
import           Data.Memory.PtrMethods
import           Data.Memory.ExtendedWords
import           Data.Memory.Encoding.Base16
import           Foreign.Storable
import           Foreign.Ptr

import           Prelude hiding (length, take, concat, replicate)
import qualified Prelude

alloc :: ByteArray ba => Int -> (Ptr p -> IO ()) -> IO ba
alloc n f = snd `fmap` allocRet n f

create :: ByteArray ba => Int -> (Ptr p -> IO ()) -> IO ba
create n f = alloc n f

allocAndFreeze :: ByteArray a => Int -> (Ptr p -> IO ()) -> a
allocAndFreeze sz f = unsafeDoIO (alloc sz f)
{-# NOINLINE allocAndFreeze #-}

unsafeCreate :: ByteArray a => Int -> (Ptr p -> IO ()) -> a
unsafeCreate sz f = unsafeDoIO (alloc sz f)
{-# NOINLINE unsafeCreate #-}

empty :: ByteArray a => a
empty = unsafeDoIO (alloc 0 $ \_ -> return ())

-- | Pack a list of bytes into a bytearray
pack :: ByteArray a => [Word8] -> a
pack l = unsafeCreate (Prelude.length l) (fill 0 l)
  where fill _ []     _ = return ()
        fill i (x:xs) p = pokeByteOff p i x >> fill (i+1) xs p

-- | Un-pack a bytearray into a list of bytes
unpack :: ByteArrayAccess a => a -> [Word8]
unpack bs = loop 0
  where !len = length bs
        loop i
            | i == len  = []
            | otherwise =
                let !v = unsafeDoIO $ withByteArray bs (\p -> peekByteOff p i)
                 in v : loop (i+1)

-- | Create a xor of bytes between a and b.
--
-- the returns byte array is the size of the smallest input.
xor :: (ByteArrayAccess a, ByteArrayAccess b, ByteArray c) => a -> b -> c
xor a b =
    unsafeCreate n $ \pc ->
    withByteArray a  $ \pa ->
    withByteArray b  $ \pb ->
        memXor pc pa pb n
  where
        n  = min la lb
        la = length a
        lb = length b

index :: ByteArrayAccess a => a -> Int -> Word8
index b i = unsafeDoIO $ withByteArray b $ \p -> peek (p `plusPtr` i)

split :: ByteArray bs => Int -> bs -> (bs, bs)
split n bs
    | n <= 0    = (empty, bs)
    | n >= len  = (bs, empty)
    | otherwise = unsafeDoIO $ do
        withByteArray bs $ \p -> do
            b1 <- alloc n $ \r -> memCopy r p n
            b2 <- alloc (len - n) $ \r -> memCopy r (p `plusPtr` n) (len - n)
            return (b1, b2)
  where len = length bs

take :: ByteArray bs => Int -> bs -> bs
take n bs =
    unsafeCreate m $ \d -> withByteArray bs $ \s -> memCopy d s m
  where
        m   = min len n
        len = length bs

concat :: ByteArray bs => [bs] -> bs
concat []    = empty
concat allBs = unsafeCreate total (loop allBs)
  where
        total = sum $ map length allBs

        loop []     _   = return ()
        loop (b:bs) dst = do
            let sz = length b
            withByteArray b $ \p -> memCopy dst p sz
            loop bs (dst `plusPtr` sz)

append :: ByteArray bs => bs -> bs -> bs
append b1 b2 = concat [b1,b2]

copy :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO ()) -> IO bs2
copy bs f =
    alloc (length bs) $ \d -> do
        withByteArray bs $ \s -> memCopy d s (length bs)
        f (castPtr d)

copyRet :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO a) -> IO (a, bs2)
copyRet bs f =
    allocRet (length bs) $ \d -> do
        withByteArray bs $ \s -> memCopy d s (length bs)
        f (castPtr d)

copyAndFreeze :: (ByteArrayAccess bs1, ByteArray bs2) => bs1 -> (Ptr p -> IO ()) -> bs2
copyAndFreeze bs f =
    unsafeCreate (length bs) $ \d -> do
        withByteArray bs $ \s -> memCopy d s (length bs)
        f (castPtr d)

replicate :: ByteArray ba => Int -> Word8 -> ba
replicate 0 _ = empty
replicate n b = unsafeCreate n $ \ptr -> memSet ptr b n
{-# NOINLINE replicate #-}

zero :: ByteArray ba => Int -> ba
zero 0 = empty
zero n = unsafeCreate n $ \ptr -> memSet ptr 0 n
{-# NOINLINE zero #-}

eq :: (ByteArrayAccess bs1, ByteArrayAccess bs2) => bs1 -> bs2 -> Bool
eq b1 b2
    | l1 /= l2  = False
    | otherwise = unsafeDoIO $ withByteArray b1 $ \p1 -> withByteArray b2 $ \p2 -> memEqual p1 p2 l1
  where
    l1 = length b1
    l2 = length b2

-- | A constant time equality test for 2 ByteArrayAccess values.
--
-- If values are of 2 different sizes, the function will abort early
-- without comparing any bytes.
--
-- compared to == , this function will go over all the bytes
-- present before yielding a result even when knowing the
-- overall result early in the processing.
constEq :: (ByteArrayAccess bs1, ByteArrayAccess bs2) => bs1 -> bs2 -> Bool
constEq b1 b2
    | l1 /= l2  = False
    | otherwise = unsafeDoIO $ withByteArray b1 $ \p1 -> withByteArray b2 $ \p2 -> memConstEqual p1 p2 l1
  where
    l1 = length b1
    l2 = length b2

toW64BE :: ByteArrayAccess bs => bs -> Int -> BE Word64
toW64BE bs ofs = unsafeDoIO $ withByteArray bs $ \p -> peek (p `plusPtr` ofs)

toW64LE :: ByteArrayAccess bs => bs -> Int -> LE Word64
toW64LE bs ofs = unsafeDoIO $ withByteArray bs $ \p -> peek (p `plusPtr` ofs)

mapAsWord128 :: ByteArray bs => (Word128 -> Word128) -> bs -> bs
mapAsWord128 f bs =
    unsafeCreate len $ \dst ->
    withByteArray bs $ \src ->
        loop (len `div` 16) dst src
  where
        len        = length bs
        loop :: Int -> Ptr (BE Word64) -> Ptr (BE Word64) -> IO ()
        loop 0 _ _ = return ()
        loop i d s = do
            w1 <- peek s
            w2 <- peek (s `plusPtr` 8)
            let (Word128 r1 r2) = f (Word128 (fromBE w1) (fromBE w2))
            poke d               (toBE r1)
            poke (d `plusPtr` 8) (toBE r2)
            loop (i-1) (d `plusPtr` 16) (s `plusPtr` 16)

mapAsWord64 :: ByteArray bs => (Word64 -> Word64) -> bs -> bs
mapAsWord64 f bs =
    unsafeCreate len $ \dst ->
    withByteArray bs $ \src ->
        loop (len `div` 8) dst src
  where
        len        = length bs

        loop :: Int -> Ptr (BE Word64) -> Ptr (BE Word64) -> IO ()
        loop 0 _ _ = return ()
        loop i d s = do
            w <- peek s
            let r = f (fromBE w)
            poke d (toBE r)
            loop (i-1) (d `plusPtr` 8) (s `plusPtr` 8)

convert :: (ByteArrayAccess bin, ByteArray bout) => bin -> bout
convert = flip copyAndFreeze (\_ -> return ())

convertHex :: (ByteArrayAccess bin, ByteArray bout) => bin -> bout
convertHex b =
    unsafeCreate (length b * 2) $ \bout ->
    withByteArray b             $ \bin  ->
        toHexadecimal bout bin (length b)
