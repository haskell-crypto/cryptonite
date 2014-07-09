{-# LANGUAGE CPP #-}
module Crypto.Hash.Utils.Cpu
    ( use32Hex
    ) where

use32Hex :: Bool
#ifdef ARCH_X86
use32Hex = True
#else
use32Hex = False
#endif
