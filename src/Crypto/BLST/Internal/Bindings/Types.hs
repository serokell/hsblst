-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}

-- | Types for lower-level bindings
module Crypto.BLST.Internal.Bindings.Types
  ( module Crypto.BLST.Internal.Bindings.Types
  ) where

import Prelude hiding (length)

import Control.DeepSeq (NFData(..))
import Data.ByteArray (Bytes, ScrubbedBytes)
import Data.ByteArray.Sized (SizedByteArray(..))
import Data.Coerce (coerce)
import Data.Kind (Type)
import GHC.TypeNats (Nat)

import Crypto.BLST.Internal.Demote

-- | Kind of point.
data PointKind = P1 | P2

instance Demote 'P1 where demote = P1
instance Demote 'P2 where demote = P2

-- | Size of type's representation in bytes.
type SizeOf :: Type -> Nat
type family SizeOf t

-- | Point representation.
newtype Point (a :: PointKind) = Point ( SizedByteArray (SizeOf (Point a)) Bytes )
  deriving stock (Show, Eq)

instance NFData (Point a) where
  rnf = rnf @Bytes . unSizedByteArray . coerce

-- | Affine point representation.
newtype Affine (a :: PointKind) = Affine { unAffine :: SizedByteArray (SizeOf (Affine a)) Bytes }
  deriving stock (Show, Eq)

instance NFData (Affine a) where
  rnf = rnf @Bytes . unSizedByteArray . coerce

-- | Scalar value representation.
newtype Scalar = Scalar ( SizedByteArray (SizeOf Scalar) ScrubbedBytes )
  deriving stock (Show, Eq)

instance NFData Scalar where
  rnf = rnf @ScrubbedBytes . unSizedByteArray . coerce

-- | Pairing context.
newtype PairingCtx = PairingCtx Bytes
  deriving newtype NFData

-- | Flag to choose whether values are hashed or encoded to the curve.
data EncodeMethod = Encode | Hash
  deriving stock (Eq, Enum, Bounded, Show)

instance Demote 'Hash where demote = Hash
instance Demote 'Encode where demote = Encode

-- | Serialized size of 'P1'.
type P1SerializeSize = 96

-- | Compressed serialized size of 'P1'.
type P1CompressSize = 48

-- | Serialized size of 'P2'.
type P2SerializeSize = 192

-- | Compressed serialized size of 'P2'.
type P2CompressSize = 96

-- | Scalar serialized size.
type SkSerializeSize = 32
