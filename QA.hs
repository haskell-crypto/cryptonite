{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Language.Haskell.Exts
import Language.Haskell.Exts.Pretty
import Data.List
import System.Directory
import System.FilePath
import System.Posix.Files
import System.Process
import Control.Monad
import Control.Applicative ((<$>))
import Control.Exception

import System.Console.ANSI

allowedExtensions =
    [ ScopedTypeVariables, BangPatterns, ForeignFunctionInterface, OverloadedStrings, DeriveDataTypeable ]
perModuleAllowedExtensions =
    [ ("Crypto/Hash/Utils.hs", [MagicHash])
    , ("Crypto/Internal/ByteArray.hs", [MagicHash, UnboxedTuples])
    , ("Crypto/Internal/Memory.hs", [MagicHash, UnboxedTuples])
    ]

disallowedModules =
    [ (ModuleName "System.IO.Unsafe", ModuleName "Crypto.Internal.Compat")
    , (ModuleName "Data.Byteable", ModuleName "Crypto.Internal.ByteArray")
    , (ModuleName "Data.SecureMem", ModuleName "Crypto.Internal.ByteArray")
    , (ModuleName "Control.Applicative", ModuleName "Crypto.Internal.Imports")
    ]

perModuleAllowedModules =
    [ ("Crypto/Internal/Imports.hs",
            [ ModuleName "Control.Applicative"
            ]
      )
    ]


main = do
    modules <- findAllModules
    mapM_ qa modules
  where qa file = do
            printHeader ("==== " ++ file)
            content <- readFile file
            let mexts = readExtensions content
            case mexts of
                Nothing        -> printError "failed to parsed extensions"
                Just (_, exts) -> qaExts file content exts

        qaExts file contentRaw exts = do
            printInfo "extensions" (intercalate ", " $ map show (getEnabledExts exts))

            let hasCPP = EnableExtension CPP `elem` exts

            content <- if hasCPP then processCPP file contentRaw else return contentRaw

            let mode = defaultParseMode { parseFilename = file, extensions = exts }

            case parseModuleWithMode mode content of
                ParseFailed srcLoc s -> printError ("failed to parse module: " ++ show srcLoc ++ " : " ++ s)
                ParseOk mod          -> do
                    let imports = getModulesImports mod
                    printInfo "modules" (intercalate ", "  (map (prettyPrint . importModule) imports))

                    -- check for allowed extensions
                    forM_ (getEnabledExts exts) $ \ext -> do
                        let allowed = elem ext allowedExtensions
                            allowed' = allowed || maybe False (\z -> elem ext z) (lookup file perModuleAllowedExtensions)
                        unless allowed' $ printWarningExtension ext

                    -- check for disallowed modules
                    forM_ (map importModule $ getModulesImports mod) $ \impMod ->
                        case lookup impMod disallowedModules of
                            Nothing                                   -> return ()
                            Just newMod | file == moduleToFile impMod -> return ()
                                        | otherwise                   -> do
                                let allowed = case lookup file perModuleAllowedModules of
                                                 Nothing          -> False
                                                 Just allowedMods -> elem impMod allowedMods
                                unless allowed $ printWarningImport impMod newMod
                    
        moduleToFile (ModuleName m) =
            intercalate "/" (wordsWhen (== '.') m) ++ ".hs"

        wordsWhen     :: (Char -> Bool) -> String -> [String]
        wordsWhen p s = case dropWhile p s of
                            "" -> []
                            s' -> w : wordsWhen p s'' where (w, s'') = break p s'

processCPP file content = do
    contentProcessed <- readProcess "cpphs" [d minVersionBase] content
    return $ simpleCPP contentProcessed
  where

    d s = "-D" ++ s
    minVersionBase = "MIN_VERSION_base(a,b,c)=(((a) >= 4) && ((b) >= 7))"

    -- simple CPP just strip # starting line
    simpleCPP = unlines . filter (not . isHashStart) . lines
      where
            isHashStart s = case dropWhile (flip elem " \t\v") s of
                                []    -> False
                                '#':_ -> True
                                _     -> False

------------------------------------------------------------------------

printHeader s =
    setSGR [SetColor Foreground Vivid Green] >> putStrLn s >> setSGR []
printInfo k v =
    setSGR [SetColor Foreground Vivid Blue] >> putStr k >> setSGR [] >> putStr ": " >> putStrLn v
printError s =
    setSGR [SetColor Foreground Vivid Red] >> putStrLn s >> setSGR []

printWarningImport (ModuleName expected) (ModuleName actual) =
    setSGR [SetColor Foreground Vivid Yellow] >> putStrLn ("warning: use module " ++ expected ++ " instead of " ++ actual) >> setSGR []

printWarningExtension ext =
    setSGR [SetColor Foreground Vivid Yellow] >> putStrLn ("warning: use extension " ++ show ext) >> setSGR []
getModulesImports (Module _ _ _ _ _ imports _) = imports

getEnabledExts = foldl doAcc []
  where doAcc acc (EnableExtension e) = e : acc
        doAcc acc _                   = acc

------------------------------------------------------------------------

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
