-- CHANGELOG since copy:
-- * refactor to allow more check than AESNI support
--
-- copied from Setup.hs from cipher-aes128 - Original Author : tommd
{-# LANGUAGE CPP #-}
import Control.Monad (unless)
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Utils
import Distribution.Simple.Program
import Distribution.Verbosity
import System.Process
import System.Exit
import System.IO (hFlush, stdout)

main :: IO ()
main = defaultMainWithHooks $ simpleUserHooks { buildHook = bh }
 where
    bh pd lbi uh bf = do
        let ccProg = Program "gcc" undefined undefined undefined
            hcProg = Program "ghc" undefined undefined undefined
            mConf  = lookupProgram ccProg (withPrograms lbi)
            hcConf = lookupProgram hcProg (withPrograms lbi)
            err = error "Could not determine C compiler"
            _cc  = locationPath . programLocation  . maybe err id $ mConf
            hc  = locationPath . programLocation  . maybe err id $ hcConf
        b1 <- compileCheck SupportAes hc
        b2 <- compileCheck SupportPclMul hc
        b3 <- compileCheck SupportInt128 hc
        let extraFlags = b1 ++ b2 ++ b3
            newWithPrograms  = userSpecifyArgs "ghc" (toHaskellCOptions extraFlags)
                             $ userSpecifyArgs "gcc" extraFlags
                             $ withPrograms lbi
            lbiNew = if not $ null extraFlags then (lbi {withPrograms = newWithPrograms }) else lbi
        buildHook simpleUserHooks pd lbiNew uh bf

data Support = SupportAes | SupportPclMul | SupportInt128
    deriving (Show,Eq,Enum,Bounded)

toFlags :: Support -> [String]
toFlags SupportAes    = ["-maes", "-mssse3", "-DHAVE_AESNI_INTRINSICS" ]
toFlags SupportPclMul = ["-mpclmul", "-mssse3", "-DHAVE_PCLMUL_INTRINSICS" ]
toFlags SupportInt128 = ["-DHAVE_INT128_SUPPORT"]

toProgram :: Support -> [String]
toProgram SupportAes =
    [ "#include <wmmintrin.h>"
    , "int real_main() {"
    , "return 0; }"
    ]
toProgram SupportPclMul =
    [ "#include <wmmintrin.h>"
    , "int real_main() {"
    , "return 0; }"
    ]
toProgram SupportInt128 =
    [ ""
    , "int real_main() {"
    , "   __uint128_t valu = 0;"
    , "   __int128_t vali = 0;"
    , "return 0; }"
    ]

toHaskellCOptions = map ("-optc" ++)

compileCheck support cc = withTempDirectory normal "" (show support) $ \tmpDir -> do
    let fp = tmpDir ++ "/" ++ show support ++ ".c"
    writeFile fp (unlines $ toProgram support)
    ec <- myRawSystemExitCode normal cc (toHaskellCOptions (toFlags support) ++ ["-c", fp])
    notice normal $ "Result of " ++ (show support) ++ " Test: " ++ show (ec == ExitSuccess)
    return $ if (ec == ExitSuccess) then toFlags support else []

myRawSystemExitCode :: Verbosity -> FilePath -> [String] -> IO ExitCode
#if __GLASGOW_HASKELL__ >= 704
-- We know for sure, that if GHC >= 7.4 implies Cabal >= 1.14
myRawSystemExitCode = rawSystemExitCode
#else
-- Legacy branch:
-- We implement our own 'rawSystemExitCode', this will even work if
-- the user happens to have Cabal >= 1.14 installed with GHC 7.0 or
-- 7.2
myRawSystemExitCode verbosity path args = do
    printRawCommandAndArgs verbosity path args
    hFlush stdout
    exitcode <- rawSystem path args
    unless (exitcode == ExitSuccess) $ do
        debug verbosity $ path ++ " returned " ++ show exitcode
    return exitcode
  where
    printRawCommandAndArgs :: Verbosity -> FilePath -> [String] -> IO ()
    printRawCommandAndArgs verbosity path args
      | verbosity >= deafening = print (path, args)
      | verbosity >= verbose = putStrLn $ unwords (path : args)
      | otherwise = return ()
#endif
