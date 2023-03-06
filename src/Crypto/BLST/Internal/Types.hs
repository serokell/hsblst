-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- | Types used for the high-level interface.
module Crypto.BLST.Internal.Types
  ( module Crypto.BLST.Internal.Types
  ) where

import Control.DeepSeq (NFData)
import Data.Kind (Type)

import Crypto.BLST.Internal.Bindings.Types
import Crypto.BLST.Internal.Classy (Curve, CurveToMsgPoint, CurveToPkPoint)

-- | Representation for the secret key.
newtype SecretKey = SecretKey Scalar
  deriving stock (Eq, Show)
  deriving newtype NFData

-- | Public key representation.
type PublicKey :: Curve -> Type
newtype PublicKey c = PublicKey (Affine (CurveToPkPoint c))
  deriving stock (Eq, Show)
  deriving newtype NFData

-- | Signature representation.
type Signature :: Curve -> EncodeMethod -> Type
newtype Signature c m = Signature (Affine (CurveToMsgPoint c))
  deriving stock (Eq, Show)
  deriving newtype NFData
