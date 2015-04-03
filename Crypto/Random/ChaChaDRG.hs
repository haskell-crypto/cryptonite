-- |
-- Module      : Crypto.Random.ChaChaDRG
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Random.ChaChaDRG
    ( ChaChaDRG
    , initialize
    , initializeWords
    ) where

import Crypto.Random.Types
import Crypto.Internal.ByteArray
import Data.SecureMem
import Data.Word
import Foreign.Storable (pokeElemOff)

import qualified Crypto.Cipher.ChaCha as C

instance DRG ChaChaDRG where
    randomBytesGenerate = generate

-- | ChaCha Deterministic Random Generator
newtype ChaChaDRG = ChaChaDRG C.StateSimple

-- | Initialize a new ChaCha context with the number of rounds,
-- the key and the nonce associated.
initialize :: ByteArray seed
           => seed        -- ^ 40 bytes of seed
           -> ChaChaDRG   -- ^ the initial ChaCha state
initialize seed = ChaChaDRG $ C.initializeSimple seed

-- | Initialize a new ChaCha context from 5-tuple of words64.
-- This interface is useful when creating a RNG out of tests generators (e.g. QuickCheck).
initializeWords :: (Word64, Word64, Word64, Word64, Word64) -> ChaChaDRG
initializeWords (a,b,c,d,e) = initialize (byteArrayAllocAndFreeze 40 fill :: SecureMem)
  where fill s = mapM_ (uncurry (pokeElemOff s)) [(0,a), (1,b), (2,c), (3,d), (4,e)]

generate :: ByteArray byteArray => Int -> ChaChaDRG -> (byteArray, ChaChaDRG)
generate nbBytes st@(ChaChaDRG prevSt)
    | nbBytes <= 0 = (empty, st)
    | otherwise    = let (output, newSt) = C.generateSimple prevSt nbBytes in (output, ChaChaDRG newSt)
