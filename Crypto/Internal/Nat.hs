{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.Internal.Nat
    ( type IsDivisibleBy8
    , type IsAtMost, type IsAtLeast
    , byteLen
    , integralNatVal
    ) where

import           GHC.TypeLits

byteLen :: (KnownNat bitlen, IsDivisibleBy8 bitlen, Num a) => proxy bitlen -> a
byteLen d = fromInteger (natVal d `div` 8)

integralNatVal :: (KnownNat bitlen, Num a) => proxy bitlen -> a
integralNatVal = fromInteger . natVal

type family IsLE (bitlen :: Nat) (n :: Nat) (c :: Bool) where
    IsLE bitlen n 'True  = 'True
#if MIN_VERSION_base(4,9,0)
    IsLE bitlen n 'False = TypeError
      (     ('Text "bitlen " ':<>: 'ShowType bitlen ':<>: 'Text " is greater than " ':<>: 'ShowType n)
      ':$$: ('Text "You have tried to use an invalid Digest size. Please, refer to the documentation.")
      )
#else
    IsLE bitlen n 'False = 'False
#endif

-- | ensure the given `bitlen` is lesser or equal to `n`
--
type IsAtMost  (bitlen :: Nat) (n :: Nat) = IsLE bitlen n (bitlen <=? n) ~ 'True

type family IsGE (bitlen :: Nat) (n :: Nat) (c :: Bool) where
    IsGE bitlen n 'True  = 'True
#if MIN_VERSION_base(4,9,0)
    IsGE bitlen n 'False = TypeError
      (     ('Text "bitlen " ':<>: 'ShowType bitlen ':<>: 'Text " is lesser than " ':<>: 'ShowType n)
      ':$$: ('Text "You have tried to use an invalid Digest size. Please, refer to the documentation.")
      )
#else
    IsGE bitlen n 'False = 'False
#endif

-- | ensure the given `bitlen` is greater or equal to `n`
--
type IsAtLeast (bitlen :: Nat) (n :: Nat) = IsGE bitlen n (n <=? bitlen) ~ 'True

type family IsDiv8 (bitLen :: Nat) (n :: Nat) where
    IsDiv8 bitLen 0 = 'True
#if MIN_VERSION_base(4,9,0)
    IsDiv8 bitLen 1 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 2 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 3 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 4 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 5 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 6 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
    IsDiv8 bitLen 7 = TypeError ('Text "bitLen " ':<>: 'ShowType bitLen ':<>: 'Text " is not divisible by 8")
#else
    IsDiv8 bitLen 1 = 'False
    IsDiv8 bitLen 2 = 'False
    IsDiv8 bitLen 3 = 'False
    IsDiv8 bitLen 4 = 'False
    IsDiv8 bitLen 5 = 'False
    IsDiv8 bitLen 6 = 'False
    IsDiv8 bitLen 7 = 'False
#endif
    IsDiv8 bitLen n = IsDiv8 n (Mod8 n)

type family Mod8 (n :: Nat) where
    Mod8 0 = 0
    Mod8 1 = 1
    Mod8 2 = 2
    Mod8 3 = 3
    Mod8 4 = 4
    Mod8 5 = 5
    Mod8 6 = 6
    Mod8 7 = 7
    Mod8 8 = 0
    Mod8 9 = 1
    Mod8 10 = 2
    Mod8 11 = 3
    Mod8 12 = 4
    Mod8 13 = 5
    Mod8 14 = 6
    Mod8 15 = 7
    Mod8 16 = 0
    Mod8 17 = 1
    Mod8 18 = 2
    Mod8 19 = 3
    Mod8 20 = 4
    Mod8 21 = 5
    Mod8 22 = 6
    Mod8 23 = 7
    Mod8 24 = 0
    Mod8 25 = 1
    Mod8 26 = 2
    Mod8 27 = 3
    Mod8 28 = 4
    Mod8 29 = 5
    Mod8 30 = 6
    Mod8 31 = 7
    Mod8 32 = 0
    Mod8 33 = 1
    Mod8 34 = 2
    Mod8 35 = 3
    Mod8 36 = 4
    Mod8 37 = 5
    Mod8 38 = 6
    Mod8 39 = 7
    Mod8 40 = 0
    Mod8 41 = 1
    Mod8 42 = 2
    Mod8 43 = 3
    Mod8 44 = 4
    Mod8 45 = 5
    Mod8 46 = 6
    Mod8 47 = 7
    Mod8 48 = 0
    Mod8 49 = 1
    Mod8 50 = 2
    Mod8 51 = 3
    Mod8 52 = 4
    Mod8 53 = 5
    Mod8 54 = 6
    Mod8 55 = 7
    Mod8 56 = 0
    Mod8 57 = 1
    Mod8 58 = 2
    Mod8 59 = 3
    Mod8 60 = 4
    Mod8 61 = 5
    Mod8 62 = 6
    Mod8 63 = 7
    Mod8 n = Mod8 (n - 64)

type IsDivisibleBy8 bitLen = IsDiv8 bitLen bitLen ~ 'True
