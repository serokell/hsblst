-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_HADDOCK not-home #-}
{-# LANGUAGE RoleAnnotations #-}

-- | Types used for the high-level interface.
module Crypto.BLST.Internal.Types
  ( module Crypto.BLST.Internal.Types
  ) where

import Control.DeepSeq (NFData)
import Data.Kind (Type)
import Data.Proxy (Proxy(..))
import GHC.TypeLits (KnownNat, Nat, natVal)

import Crypto.BLST.Internal.Bindings.Types
import Crypto.BLST.Internal.Classy
  (CompressedSize, Curve, CurveToMsgPoint, CurveToPkPoint, SerializedSize)

-- | Data kind flag for 'ByteSize'.
data SerializeOrCompress = Serialize | Compress

type ByteSize :: SerializeOrCompress -> Type -> Nat
-- | Size in bytes of serialized/compressed representations of basic types.
type family ByteSize soc a

-- | Convenience function to get byte size as an 'Int' value.
byteSize :: forall soc a. KnownNat (ByteSize soc a) => Int
byteSize = fromIntegral $ natVal @(ByteSize soc a) Proxy

-- | Representation for the secret key.
newtype SecretKey = SecretKey Scalar
  deriving stock (Eq, Show)
  deriving newtype NFData

type instance ByteSize 'Serialize SecretKey = SkSerializeSize

type role PublicKey nominal
-- | Public key representation.
type PublicKey :: Curve -> Type
newtype PublicKey c = PublicKey (Affine (CurveToPkPoint c))
  deriving stock (Eq, Show)
  deriving newtype NFData

type instance ByteSize 'Serialize (PublicKey c) = SerializedSize (CurveToPkPoint c)
type instance ByteSize 'Compress (PublicKey c) = CompressedSize (CurveToPkPoint c)

type role Signature nominal phantom
-- | Signature representation.
type Signature :: Curve -> EncodeMethod -> Type
newtype Signature c m = Signature (Affine (CurveToMsgPoint c))
  deriving stock (Eq, Show)
  deriving newtype NFData

type instance ByteSize 'Serialize (Signature c _) = SerializedSize (CurveToMsgPoint c)
type instance ByteSize 'Compress (Signature c _) = CompressedSize (CurveToMsgPoint c)
