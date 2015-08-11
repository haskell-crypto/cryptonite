
module Crypto.KDF.BCrypt
    ( hashPassword
    , validatePassword
    , bcrypt
    )
where

import           Control.Monad (unless, when)
import           Crypto.Cipher.Blowfish.Primitive (eksBlowfish, encrypt)
import           Crypto.Random (MonadRandom, getRandomBytes)
import           Data.ByteArray (ByteArrayAccess, ByteArray, Bytes)
import qualified Data.ByteArray as B
import           Data.ByteArray.Encoding
import           Data.Char

data BCryptHash = BCH Char Int Bytes Bytes

-- | Create a bcrypt hash for a password with a provided cost value.
--
-- Each increment of the cost approximately doubles the time taken.
-- The 16 bytes of random salt will be generated internally.
hashPassword :: (MonadRandom m, ByteArray password, ByteArray hash)
             => Int
             -- ^ The cost parameter. Should be between 4 and 31 (inclusive).
             -- Values which lie outside this range will be adjusted accordingly.
             -> password
             -- ^ The password.
             -> m hash
             -- ^ The bcrypt hash in standard format.
hashPassword cost password = do
    salt <- getRandomBytes 16
    return $ bcrypt cost (salt :: Bytes) password

-- | Create a bcrypt hash for a password with a provided cost value and salt.
bcrypt :: (ByteArray salt, ByteArray password, ByteArray output)
       => Int
       -- ^ The cost parameter. Should be between 4 and 31 (inclusive).
       -- Values which lie outside this range will be adjusted accordingly.
       -> salt
       -- ^ The salt. Must be 16 bytes in length or an error will be raised.
       -> password
       -- ^ The password.
       -> output
       -- ^ The bcrypt hash in standard format.
bcrypt cost salt password = B.concat [header, B.snoc costBytes dollar, b64 salt, b64 hash]
  where
    hash   = rawHash 'b' realCost salt password
    header = B.pack [dollar, fromIntegral (ord '2'), fromIntegral (ord 'a'), dollar]
    dollar = fromIntegral (ord '$')
    zero   = fromIntegral (ord '0')
    costBytes  = B.pack [zero + fromIntegral (realCost `div` 10), zero + fromIntegral (realCost `mod` 10)]
    realCost
        | cost < 4  = 4
        | cost > 31 = 31
        | otherwise = cost

    b64 :: (ByteArray ba) => ba -> ba
    b64 = convertToBase Base64OpenBSD

-- | Check a password against a bcrypt hash
--
-- Returns @False@ if the password doesn't match the hash, or if the hash is
-- invalid or an unsupported version.
validatePassword :: (ByteArray password, ByteArray hash) => password -> hash -> Bool
validatePassword password bcHash = case parseBCryptHash bcHash of
    Right (BCH version cost salt hash) -> (rawHash version cost salt password :: Bytes) `B.constEq` hash
    Left  _                            -> False

rawHash :: (ByteArrayAccess salt, ByteArray password, ByteArray output) => Char -> Int -> salt -> password -> output
rawHash version cost salt password = B.take 23 hash
  where
    hash = loop (0 :: Int) orpheanBeholder

    loop i input
        | i < 64    = loop (i+1) (encrypt ctx input)
        | otherwise = input

    -- Truncate the password if necessary and append a null byte for C compatibility
    key = B.snoc (B.take 72 password) 0

    ctx = eksBlowfish cost salt key

    -- The BCrypt plaintext: "OrpheanBeholderScryDoubt"
    orpheanBeholder = B.pack [79,114,112,104,101,97,110,66,101,104,111,108,100,101,114,83,99,114,121,68,111,117,98,116]

-- "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
parseBCryptHash :: (ByteArray ba) => ba -> Either String BCryptHash
parseBCryptHash bc = do
    unless (B.length bc == 60     &&
            B.index bc 0 == dollar &&
            B.index bc 1 == fromIntegral (ord '2') &&
            B.index bc 3 == dollar &&
            B.index bc 6 == dollar) (Left "Invalid hash format")
    when (costTens > 3 || cost > 31 || cost < 4)  (Left "Invalid bcrypt cost")
    (salt, hash) <- decodeSaltHash (B.drop 7 bc)
    return (BCH version cost salt hash)
  where
    dollar    = fromIntegral (ord '$')
    zero      = ord '0'
    costTens  = fromIntegral (B.index bc 4) - zero
    costUnits = fromIntegral (B.index bc 5) - zero
    version   = chr (fromIntegral (B.index bc 2))
    cost      = costUnits + (if costTens == 0 then 0 else 10^costTens) :: Int

    decodeSaltHash saltHash = do
        let (s, h) = B.splitAt 22 saltHash
        salt <- convertFromBase Base64OpenBSD s
        hash <- convertFromBase Base64OpenBSD h
        return (salt, hash)
