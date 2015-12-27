
module Crypto.OTP
    ( hotp
    , OTPDigits (..)
    , resynchronize
    , totp
    )
where

import           Data.Bits (shiftL, shiftR, (.&.), (.|.))
import           Data.Time.Clock.POSIX
import           Data.List (elemIndex)
import           Data.Word
import           Foreign.Storable (pokeByteOff)
import           Crypto.Hash (HashAlgorithm, SHA1)
import           Crypto.MAC.HMAC
import           Crypto.Internal.ByteArray (ByteArrayAccess, ByteArray, Bytes)
import qualified Crypto.Internal.ByteArray as B

-- | The strength of the calculated HOTP value, namely
-- the number of digits (between 4 and 9) in the extracted value.
data OTPDigits = OTP4 | OTP5 | OTP6 | OTP7 | OTP8 | OTP9

hotp :: ByteArrayAccess key
    => OTPDigits
    -- ^ Number of digits in the HOTP value extracted from the calculated HMAC
    -> key
    -- ^ Shared secret between the client and server
    -> Word64
    -- ^ Counter value synchronized between the client and server
    -> Word32
    -- ^ The HOTP value
hotp d k c = dt `mod` digitsPower d
  where
    mac = hmac k (fromW64BE c :: Bytes) :: HMAC SHA1
    offset = fromIntegral (B.index mac (B.length mac - 1) .&. 0xf)
    dt = (fromIntegral (B.index mac offset       .&. 0x7f) `shiftL` 24) .|.
         (fromIntegral (B.index mac (offset + 1) .&. 0xff) `shiftL` 16) .|.
         (fromIntegral (B.index mac (offset + 2) .&. 0xff) `shiftL`  8) .|.
         fromIntegral  (B.index mac (offset + 3) .&. 0xff)

-- | Attempt to resynchronize the server's counter value
-- with the client, given a sequence of HOTP values.
resynchronize :: ByteArrayAccess key
    => OTPDigits
    -> Word32
    -- ^ The look-ahead window parameter. Up to this many values will
    -- be calculated and checked against the value(s) submitted by the client
    -> key
    -- ^ The shared secret
    -> Word64
    -- ^ The current server counter value
    -> (Word32, [Word32])
    -- ^ The first OTP submitted by the client and a list of additional
    -- sequential OTPs (which may be empty)
    -> Maybe Word64
    -- ^ The new counter value, synchronized with the client's current counter
    -- or Nothing if the submitted OTP values didn't match anywhere within the window
resynchronize d s k c (p1, extras) = do
    offBy <- fmap fromIntegral (elemIndex p1 range)
    checkExtraOtps (c + offBy + 1) extras
  where
    checkExtraOtps ctr [] = Just ctr
    checkExtraOtps ctr (p:ps)
        | hotp d k ctr /= p = Nothing
        | otherwise         = checkExtraOtps (ctr + 1) ps

    range = map (hotp d k)[c..c + fromIntegral s]

digitsPower :: OTPDigits -> Word32
digitsPower OTP4 = 10000
digitsPower OTP5 = 100000
digitsPower OTP6 = 1000000
digitsPower OTP7 = 10000000
digitsPower OTP8 = 100000000
digitsPower OTP9 = 1000000000


totp :: (HashAlgorithm hash, ByteArrayAccess key)
    => hash
    -> Word32
    -- ^ The time step parameter X
    -> Word64
    -- ^ The T0 parameter in seconds. This is the Unix time from which to start
    -- counting steps (usually zero)
    -> OTPDigits
    -> key
    -- ^ The shared secret
    -> POSIXTime
    -- ^ The time for which the OTP should be calculated.
    -- This is usually the current time as returned by @Data.Time.Clock.POSIX.getPOSIXTime@
    -> Word32
    -- ^ The OTP value
totp h x t0 d k now = hotp d k t
  where
    t = floor ((now - fromIntegral t0) / fromIntegral x)

-- TODO: Put this in memory package
fromW64BE :: (ByteArray ba) => Word64 -> ba
fromW64BE n = B.allocAndFreeze 8 $ \p -> do
    pokeByteOff p 0 (fromIntegral (shiftR n 56) :: Word8)
    pokeByteOff p 1 (fromIntegral (shiftR n 48) :: Word8)
    pokeByteOff p 2 (fromIntegral (shiftR n 40) :: Word8)
    pokeByteOff p 3 (fromIntegral (shiftR n 32) :: Word8)
    pokeByteOff p 4 (fromIntegral (shiftR n 24) :: Word8)
    pokeByteOff p 5 (fromIntegral (shiftR n 16) :: Word8)
    pokeByteOff p 6 (fromIntegral (shiftR n  8) :: Word8)
    pokeByteOff p 7 (fromIntegral n             :: Word8)
