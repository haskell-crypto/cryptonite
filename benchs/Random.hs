{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE PackageImports #-}
module Main where

import Gauge.Main
import Control.Monad

import "cryptonite" Crypto.Random

import qualified "cprng-aes" Crypto.Random.AESCtr as A
import qualified "crypto-random" Crypto.Random as A

import Data.ByteString (ByteString)

tests = [(32, 4096), (64, 4096) ]

evalBsList :: (a -> [ByteString]) -> a -> Benchmarkable
evalBsList = nf

toBench drg (chunkSize, total) =
    bench ("chunk=" ++ show chunkSize ++ " total=" ++ show total) $ evalBsList (run drg) 0
  where
    run !r !n
        | n >= total = []
        | otherwise  =
            let (!b, r') = randomBytesGenerate chunkSize r
            in b : run r' (n + chunkSize)

toBenchCPRG drg (chunkSize, total) =
    bench ("chunk=" ++ show chunkSize ++ " total=" ++ show total) $ evalBsList (run drg) 0
  where
    run !r !n
        | n >= total = []
        | otherwise  =
            let (!b, r') = A.cprgGenerate chunkSize r
            in b : run r' (n + chunkSize)

main = do
    chachaDrg <- drgNew
    systemDrg <- getSystemDRG
    aesCPRG   <- A.makeSystem
    defaultMain 
        [ bgroup "chacha" $ map (toBench chachaDrg) tests
        , bgroup "system" $ map (toBench systemDrg) tests
        , bgroup "aesctr" $ map (toBenchCPRG aesCPRG) tests
        ]
