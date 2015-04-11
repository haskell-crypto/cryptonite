-- |
-- Module      : Crypto.Error.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Cryptographic Error enumeration and handling
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Error.Types
    ( CryptoError(..)
    , CryptoFailable(..)
    , throwCryptoErrorIO
    , throwCryptoError
    ) where

import qualified Control.Exception as E
import           Data.Data

import           Crypto.Internal.Imports

-- | Enumeration of all possible errors that can be found in this library
data CryptoError =
    -- symmetric cipher errors
      CryptoError_KeySizeInvalid
    | CryptoError_IvSizeInvalid
    deriving (Show,Eq,Enum,Data,Typeable)

instance E.Exception CryptoError

-- | A simple Either like type to represent a computation that can fail
--
-- 2 possibles values are:
-- * 'CryptoPassed' : 
data CryptoFailable a =
      CryptoPassed a
    | CryptoFailed CryptoError

instance Functor CryptoFailable where
    fmap f (CryptoPassed a) = CryptoPassed (f a)
    fmap _ (CryptoFailed r) = CryptoFailed r

instance Applicative CryptoFailable where
    pure a     = CryptoPassed a
    (<*>) fm m = fm >>= \p -> m >>= \r2 -> return (p r2)
instance Monad CryptoFailable where
    return a = CryptoPassed a
    (>>=) m1 m2 = do
        case m1 of
            CryptoPassed a -> m2 a
            CryptoFailed e -> CryptoFailed e

throwCryptoErrorIO :: CryptoFailable a -> IO a
throwCryptoErrorIO (CryptoFailed e) = E.throwIO e
throwCryptoErrorIO (CryptoPassed r) = return r

throwCryptoError :: CryptoFailable a -> a
throwCryptoError (CryptoFailed e) = E.throw e
throwCryptoError (CryptoPassed r) = r

{-
eitherCryptoError :: CryptoFailable a -> Either CryptoError a
eitherCryptoError = undefined

maybeCryptoError :: CryptoFailable a -> Maybe a
maybeCryptoError = undefined
-}
