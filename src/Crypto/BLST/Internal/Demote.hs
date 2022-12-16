-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- | Utility class to demote promoted datatypes.
module Crypto.BLST.Internal.Demote
  ( module Crypto.BLST.Internal.Demote
  ) where

import Data.Kind (Constraint)

-- | Demotes a promoted data kind.
type Demote :: forall {k}. k -> Constraint
class Demote (x :: k) where
  -- | Returns a value corresponding to a promoted type.
  demote :: k
