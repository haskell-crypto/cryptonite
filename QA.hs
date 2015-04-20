{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Language.Haskell.Exts
import Language.Haskell.Exts.Pretty
import Data.List
import Data.IORef
import System.Directory
import System.FilePath
import System.Posix.Files
import System.Process
import Control.Monad
import Control.Applicative ((<$>), (<*>))
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
    , ("Crypto/Internal/Memory.hs",
            [ ModuleName "Data.SecureMem"
            ]
      )
    ]

data ModuleState = ModuleState
    { mWarnings :: IORef Int
    , mErrors   :: IORef Int
    }

newState :: IO ModuleState
newState = ModuleState <$> newIORef 0 <*> newIORef 0

incrWarnings :: ModuleState -> IO ()
incrWarnings st = modifyIORef (mWarnings st) (+1)

incrErrors :: ModuleState -> IO ()
incrErrors st = modifyIORef (mErrors st) (+1)

main = do
    modules <- findAllModules
    mapM_ qa modules
  where qa file = do
            st <- newState

            printHeader ("[# " ++ file ++ " #]")
            content <- readFile file
            let mexts = readExtensions content
            case mexts of
                Nothing        -> do
                    printError st "failed to parsed extensions"
                    printReport st file
                Just (_, exts) -> qaExts st file content exts

        qaExts st file contentRaw exts = do
            printInfo "extensions" (intercalate ", " $ map show (getEnabledExts exts))

            let hasCPP = EnableExtension CPP `elem` exts

            content <- if hasCPP then processCPP file contentRaw else return contentRaw

            let mode = defaultParseMode { parseFilename = file, extensions = exts }

            case parseModuleWithMode mode content of
                ParseFailed srcLoc s -> do
                    printError st ("failed to parse module: " ++ show srcLoc ++ " : " ++ s)
                    printReport st file
                ParseOk mod          -> do
                    let imports = getModulesImports mod
                    printInfo "modules" (intercalate ", "  (map (prettyPrint . importModule) imports))

                    -- check for allowed extensions
                    forM_ (getEnabledExts exts) $ \ext -> do
                        let allowed = elem ext allowedExtensions
                            allowed' = allowed || maybe False (\z -> elem ext z) (lookup file perModuleAllowedExtensions)
                        unless allowed' $ printWarningExtension st ext

                    -- check for disallowed modules
                    forM_ (map importModule $ getModulesImports mod) $ \impMod ->
                        case lookup impMod disallowedModules of
                            Nothing                                   -> return ()
                            Just newMod | file == moduleToFile impMod -> return ()
                                        | otherwise                   -> do
                                let allowed = case lookup file perModuleAllowedModules of
                                                 Nothing          -> False
                                                 Just allowedMods -> elem impMod allowedMods
                                unless allowed $ printWarningImport st impMod newMod
                    printReport st file

        report warnings errors =
            putStrLn ""
                    
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
    setSGR [SetColor Foreground Vivid Cyan] >> putStrLn s >> setSGR []
printInfo k v =
    setSGR [SetColor Foreground Vivid Blue] >> putStr k >> setSGR [] >> putStr ": " >> putStrLn v
printError st s = do
    setSGR [SetColor Foreground Vivid Red] >> putStrLn s >> setSGR []

printReport st m =
    ((,) <$> readIORef (mWarnings st) <*> readIORef (mErrors st)) >>= uncurry doPrint
  where doPrint :: Int -> Int -> IO ()
        doPrint warnings errors
            | warnings == 0 && errors == 0 = do
                start
                setSGR [SetColor Foreground Vivid Green] >> putStrLn "SUCCESS" >> setSGR []
            | otherwise = do
                let color = if errors == 0 then Yellow else Red
                start
                setSGR [SetColor Foreground Vivid color] >> putStrLn (show errors ++ " errors " ++ show warnings ++ " warnings") >> setSGR []
        start = do
            setSGR [SetColor Foreground Vivid Cyan] >> putStr "===> " >> setSGR []
            putStr (m ++ " : ")

printWarningImport st (ModuleName expected) (ModuleName actual) = do
    incrWarnings st
    setSGR [SetColor Foreground Vivid Yellow] >> putStrLn ("warning: use module " ++ expected ++ " instead of " ++ actual) >> setSGR []

printWarningExtension st ext = do
    incrWarnings st
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
