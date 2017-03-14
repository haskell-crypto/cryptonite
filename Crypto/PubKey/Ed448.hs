-- |
-- Module      : Crypto.PubKey.Ed448
-- License     : BSD-style
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : unknown
--
-- Ed448 support
--
-- /Functions and types exported here will be DEPRECATED in a future version./
-- For Diffie-Hellman over curve448 please use module "Crypto.PubKey.Curve448"
-- instead.
--
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}
module Crypto.PubKey.Ed448
    ( module Crypto.PubKey.Curve448
    ) where

import Crypto.PubKey.Curve448
