{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import           Language.Haskell.Exts      hiding (ModuleName)
import qualified Language.Haskell.Exts as E
import Language.Haskell.Exts.Pretty
import Data.List
import Data.IORef
import System.Directory
import System.FilePath
import System.Posix.Files
import System.Process
import System.Environment
import Control.Arrow
import Control.Monad
import Control.Applicative ((<$>), (<*>))
import Control.Exception

import System.Console.ANSI

newtype ModuleName = ModuleName String
    deriving (Show,Eq)

allowedExtensions =
    [ ScopedTypeVariables, BangPatterns, ForeignFunctionInterface, DeriveDataTypeable, ViewPatterns, GeneralizedNewtypeDeriving, ExistentialQuantification, EmptyDataDecls
    , TypeFamilies, KindSignatures, DataKinds ]
perModuleAllowedExtensions =
    [ ("Crypto/Hash/Utils.hs", [MagicHash])
    , ("Crypto/Hash/SHAKE.hs", [UndecidableInstances,TypeOperators,ConstraintKinds])
    , ("Crypto/Internal/ByteArray.hs", [MagicHash, UnboxedTuples])
    , ("Crypto/Internal/Memory.hs", [MagicHash, UnboxedTuples])
    , ("Crypto/Internal/Compat.hs", [CPP])
    , ("Crypto/Internal/CompatPrim.hs", [CPP,MagicHash,UnboxedTuples])
    , ("Crypto/Internal/Endian.hs", [CPP])
    , ("Crypto/Internal/WordArray.hs", [UnboxedTuples,MagicHash])
    , ("Crypto/Internal/Hex.hs", [Rank2Types, UnboxedTuples, MagicHash])
    , ("Crypto/Internal/DeepSeq.hs", [CPP])
    , ("Crypto/Random/Entropy/Backend.hs", [ExistentialQuantification,CPP])
    , ("Crypto/Random/Entropy/Windows.hs", [CPP])
    , ("Crypto/Cipher/Blowfish/Box.hs", [MagicHash])
    , ("Crypto/Cipher/Blowfish.hs", [CPP])
    , ("Crypto/Cipher/AES.hs", [CPP])
    , ("Crypto/Cipher/Types/Block.hs", [Rank2Types, MultiParamTypeClasses])
    , ("Crypto/Cipher/Types/AEAD.hs", [Rank2Types])
    , ("Crypto/Cipher/CAST5/Primitive.hs", [MagicHash])
    , ("Crypto/Cipher/Camellia/Primitive.hs", [MagicHash])
    , ("Crypto/Cipher/DES/Primitive.hs", [FlexibleInstances])
    , ("Crypto/Cipher/Twofish/Primitive.hs", [MagicHash])
    , ("Crypto/PubKey/Curve25519.hs", [MagicHash])
    , ("Crypto/PubKey/ECDSA.hs", [FlexibleContexts,StandaloneDeriving,UndecidableInstances])
    , ("Crypto/Number/Compat.hs", [UnboxedTuples,MagicHash,CPP])
    , ("Crypto/System/CPU.hs", [CPP])
    ]

disallowedModules =
    [ (ModuleName "System.IO.Unsafe", ModuleName "Crypto.Internal.Compat")
    , (ModuleName "Data.Byteable", ModuleName "Crypto.Internal.ByteArray")
    , (ModuleName "Data.SecureMem", ModuleName "Crypto.Internal.ByteArray")
    , (ModuleName "Data.ByteString", ModuleName "Crypto.Internal.ByteArray")
    , (ModuleName "Control.Applicative", ModuleName "Crypto.Internal.Imports")
    ]

perModuleAllowedModules :: [(FilePath, [ModuleName])]
perModuleAllowedModules =
    [ ("Crypto/Internal/Imports.hs",
            [ ModuleName "Control.Applicative"
            ]
      )
    , ("Crypto/Internal/Memory.hs",
            [ ModuleName "Data.SecureMem"
            ]
      )
    , ("Crypto/Internal/ByteArray.hs",
            [ ModuleName "Data.ByteString"
            ]
      )
    , ("Crypto/Internal/Bytes.hs",
            [ ModuleName "Data.ByteString"
            ]
      )
    , ("Crypto/Internal/Compat.hs",
            [ ModuleName "System.IO.Unsafe"
            ]
      )
    , ("Crypto/Random/SystemDRG.hs",
            [ ModuleName "System.IO.Unsafe"
            ]
      )
    ]

data Issue =
      Issue_FailedToParseExtension
    | Issue_FailedToParseModule SrcLoc String
    | Issue_Extension String
    | Issue_Import ModuleName ModuleName
    deriving (Eq)

prettyIssue Issue_FailedToParseExtension = "failed to parse extension"
prettyIssue (Issue_FailedToParseModule loc p) = "failed to parse module : " ++ show loc ++ " : " ++ p
prettyIssue (Issue_Extension e) = "extension not authorized: " ++ e
prettyIssue (Issue_Import (ModuleName old) (ModuleName new)) = "import : " ++ old ++ " should be : " ++ show new

data IssueLevel =
      IssueFatal
    | IssueError
    | IssueWarning
    | IssueUnknown
    deriving (Show,Eq)

getIssueLevel :: Issue -> IssueLevel
getIssueLevel Issue_FailedToParseExtension   = IssueFatal
getIssueLevel (Issue_FailedToParseModule {}) = IssueFatal
getIssueLevel _ = IssueUnknown

data InfoVal =
      InfoValList [String]
    | InfoValString String
    deriving (Show,Eq)

data ModuleState = ModuleState
    { mInfo   :: IORef [(String, InfoVal)]
    , mIssues :: IORef [Issue]
    }

data ModuleQA = ModuleQA FilePath [(String, InfoVal)] [Issue]
    deriving (Eq)

moduleGetIssues :: ModuleQA -> [Issue]
moduleGetIssues (ModuleQA _ _ is) = is

newState :: IO ModuleState
newState = ModuleState <$> newIORef [] <*> newIORef []

freezeState :: FilePath -> ModuleState -> IO ModuleQA
freezeState file (ModuleState info issues) = ModuleQA file <$> readIORef info <*> readIORef issues

data Options = Options
    { optionWarningIsError :: Bool
    }

defaultOptions = Options
    { optionWarningIsError = False
    }

parseArgs opts []     = opts
parseArgs opts (x:xs) =
    let nopts = case x of
                "-Werror" -> opts { optionWarningIsError = True }
                _         -> opts
     in parseArgs nopts xs

main = do
    options <- parseArgs defaultOptions <$> getArgs
    modules <- findAllModules
    qas     <- mapM checkModule modules
    mapM_ report qas
    summary qas

  where
        summary :: [ModuleQA] -> IO ()
        summary l = do
            let (succeeded, failed) = (length *** length) $ partition (null . moduleGetIssues) l
            putStrLn ("failed: " ++ show failed ++ " succeeded: " ++ show succeeded)

        report :: ModuleQA -> IO ()
        report (ModuleQA f infos issues)
            | null issues = do
                setColor Cyan >> putStr f >> setSGR [] >> putStr padding
                setColor Green >> putStrLn "SUCCESS" >> setSGR []
            | otherwise   = do
                setColor Cyan >> putStr f >> setSGR [] >> putStr padding
                setColor Red >> putStrLn "FAILED" >> setSGR []
                mapM_ reportIssue issues
          where
                padding = replicate padN ' '
                padN    = 64 - length f

                reportIssue issue = setColor Red >> putStr "  " >> putStrLn (prettyIssue issue) >> setSGR []

        setColor c = setSGR [SetColor Foreground Vivid c]

        checkModule file = do
            st      <- newState
            content <- readFile file
            case readExtensions content of
                Nothing        -> recordIssue st Issue_FailedToParseExtension
                Just (_, exts) -> qaExts st file content exts
            freezeState file st


        qaExts st file contentRaw exts = do
            recordInfo st "extensions" (intercalate ", " $ map show (getEnabledExts exts))

            let hasCPP = EnableExtension CPP `elem` exts

            content <- if hasCPP then processCPP file contentRaw else return contentRaw

            let mode = defaultParseMode { parseFilename = file, extensions = exts, fixities = Nothing }

            case parseModuleWithMode mode content of
                ParseFailed srcLoc s -> do
                    recordIssue st $ Issue_FailedToParseModule srcLoc s
                ParseOk mod          -> do
                    let imports = getModulesImports mod
                    recordInfo st "modules" $ InfoValList (map (prettyPrint . importModule) imports)

                    -- check for allowed extensions
                    forM_ (getEnabledExts exts) $ \ext -> do
                        let allowed = elem ext allowedExtensions
                            allowed' = allowed || maybe False (\z -> elem ext z) (lookup file perModuleAllowedExtensions)
                        unless allowed' $ recordIssue st (Issue_Extension $ show ext)

                    -- check for disallowed modules
                    forM_ (map (flattenModuleName . importModule) $ getModulesImports mod) $ \impMod ->
                        case lookup impMod disallowedModules of
                            Nothing                                   -> return ()
                            Just newMod | file == moduleToFile impMod -> return ()
                                        | otherwise                   -> do
                                let allowed = case lookup file perModuleAllowedModules of
                                                 Nothing          -> False
                                                 Just allowedMods -> elem impMod allowedMods
                                unless allowed $ recordIssue st (Issue_Import impMod newMod)

        moduleToFile (ModuleName m) =
            intercalate "/" (wordsWhen (== '.') m) ++ ".hs"

        wordsWhen     :: (Char -> Bool) -> String -> [String]
        wordsWhen p s = case dropWhile p s of
                            "" -> []
                            s' -> w : wordsWhen p s'' where (w, s'') = break p s'

processCPP file content = do
    contentProcessed <- readProcess "cpphs" [d minVersionBase, d arch] content
    return $ simpleCPP contentProcessed
  where

    d s = "-D" ++ s
    minVersionBase = "MIN_VERSION_base(a,b,c)=(((a) >= 4) && ((b) >= 7))"
    arch = "ARCH_X86"

    -- simple CPP just strip # starting line
    simpleCPP = unlines . filter (not . isHashStart) . lines
      where
            isHashStart s = case dropWhile (flip elem " \t\v") s of
                                []    -> False
                                '#':_ -> True
                                _     -> False

------------------------------------------------------------------------

recordIssue st s =
    modifyIORef (mIssues st) ((:) s)

recordInfo st n f = return ()

getModulesImports (Module _ _ _ imports _) = imports

flattenModuleName (E.ModuleName _ mn) = ModuleName mn

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
