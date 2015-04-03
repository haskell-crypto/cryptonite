{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Language.Haskell.Exts
import Data.List
import System.Directory
import System.FilePath
import System.Posix.Files
import Control.Monad
import Control.Applicative ((<$>))
import Control.Exception


main = do
    modules <- findAllModules
    mapM_ qa modules
  where qa file = do
            putStrLn ("==== " ++ file)
            content <- readFile file
            let mexts = readExtensions content
            case mexts of
                Nothing        -> printError "[ERR] failed to parsed extension"
                Just (_, exts) -> putStrLn ("extensions : " ++ (intercalate ", " $ map show exts))
        printError = putStrLn

findAllModules :: IO [FilePath]
findAllModules = dirTraverse "Crypto" fileCallback dirCallback []
  where
        fileCallback a m = return (if isSuffixOf ".hs" m then (m:a) else a)
        dirCallback a d
            | isSuffixOf "/.git" d = return (False, a)
            | otherwise            = return (True, a)

-- | Traverse directories and files starting from the @rootDir
dirTraverse :: FilePath
            -> (a -> FilePath -> IO a)
            -> (a -> FilePath -> IO (Bool, a))
            -> a
            -> IO a
dirTraverse rootDir fFile fDir a = loop a rootDir
  where loop a dir = do
            content <- try $ getDir dir
            case content of
                Left (exn :: SomeException) -> return a
                Right l  -> foldM (processEnt dir) a l
        processEnt dir a ent = do
            let fp = dir </> ent
            stat <- getSymbolicLinkStatus fp
            case (isDirectory stat, isRegularFile stat) of
                (True,_)     -> do (process,a') <- fDir a fp
                                   if process
                                      then loop a' fp
                                      else return a'
                (False,True)  -> fFile a fp
                (False,False) -> return a
        getDir dir = filter (not . flip elem [".",".."]) <$> getDirectoryContents dir
