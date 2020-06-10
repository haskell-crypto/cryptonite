-- |
-- Module      : Crypto.Internal.ByteArray
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple and efficient byte array types
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}
module Crypto.Internal.ByteArray
    ( module Data.ByteArray
    , module Data.ByteArray.Mapping
    , module Data.ByteArray.Encoding
    , constAllZero
    , unsafeMapWords
    ) where

import Data.ByteArray
import Data.ByteArray.Mapping
import Data.ByteArray.Encoding

import Data.Bits ((.|.))
import Data.Foldable (for_)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable, peekByteOff, peekElemOff, pokeElemOff, sizeOf)

import Crypto.Internal.Compat (unsafeDoIO)

constAllZero :: ByteArrayAccess ba => ba -> Bool
constAllZero b = unsafeDoIO $ withByteArray b $ \p -> loop p 0 0
  where
    loop :: Ptr b -> Int -> Word8 -> IO Bool
    loop p i !acc
        | i == len  = return $! acc == 0
        | otherwise = do
            e <- peekByteOff p i
            loop p (i+1) (acc .|. e)
    len = Data.ByteArray.length b

-- | Apply a function to every element of a byte array.
-- Assumes the array is of size some integer multiple of the element.
unsafeMapWords :: forall a ba1 ba2
                . (ByteArrayAccess ba1, ByteArray ba2, Storable a)
               => (a -> a) -> ba1 -> ba2
unsafeMapWords f prevSt = unsafeDoIO $ do
    newSt  <- copy prevSt (\_ -> return ())
    withByteArray newSt $ \stPtr -> do
        let sz = Data.ByteArray.length prevSt `div` sizeOf (undefined :: a)
        for_ [0 .. pred sz] $ \i -> do
            w <- peekElemOff stPtr i
            pokeElemOff stPtr i (f w)
    return newSt
