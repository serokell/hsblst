-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# LANGUAGE TypeFamilyDependencies #-}
{-# OPTIONS_HADDOCK not-home #-}

-- | Bindings with class.
module Crypto.BLST.Internal.Classy
  ( module Crypto.BLST.Internal.Classy
  ) where

import Data.ByteArray (ByteArrayAccess(..), Bytes)
import Data.ByteArray.Sized (SizedByteArray)
import Data.Kind (Constraint)
import GHC.TypeNats (KnownNat, Nat)

import Crypto.BLST.Internal.Bindings
import Crypto.BLST.Internal.Demote

-- | Curve data kind.
data Curve = G1 | G2

instance Demote 'G1 where demote = G1
instance Demote 'G2 where demote = G2

-- | Public key point type depending on the curve.
type CurveToPkPoint :: Curve -> PointKind
type family CurveToPkPoint c = r | r -> c where
  CurveToPkPoint 'G1 = 'P1
  CurveToPkPoint 'G2 = 'P2

-- | Message/signature point depending on the curve.
type CurveToMsgPoint :: Curve -> PointKind
type family CurveToMsgPoint c = r | r -> c where
  CurveToMsgPoint 'G1 = 'P2
  CurveToMsgPoint 'G2 = 'P1

-- | Size of serialized point.
type SerializedSize :: PointKind -> Nat
type family SerializedSize p = r | r -> p where
  SerializedSize 'P1 = P1SerializeSize
  SerializedSize 'P2 = P2SerializeSize

-- | Size of compressed serialized point.
type CompressedSize :: PointKind -> Nat
type family CompressedSize p = r | r -> p where
  CompressedSize 'P1 = P1CompressSize
  CompressedSize 'P2 = P2CompressSize

-- | Class for operations on curves.
type IsCurve :: Curve -> Constraint
class (IsPoint (CurveToMsgPoint c), IsPoint (CurveToPkPoint c)) => IsCurve c where
  skToPkPoint :: Scalar -> IO (Point (CurveToPkPoint c))
  signPk :: Point (CurveToMsgPoint c) -> Scalar -> IO (Point (CurveToMsgPoint c))
  coreVerifyPk
    :: (ByteArrayAccess ba, ByteArrayAccess ba2)
    => Affine (CurveToPkPoint c)
    -> Affine (CurveToMsgPoint c)
    -> EncodeMethod
    -> ba
    -> Maybe ba2
    -> IO BlstError
  pairingChkNAggrPk
    :: ByteArrayAccess ba
    => PairingCtx
    -> Affine (CurveToPkPoint c)
    -> Bool
    -> Maybe (Affine (CurveToMsgPoint c))
    -> Bool
    -> ba
    -> IO BlstError

instance IsCurve 'G1 where
  skToPkPoint = skToPkInG1
  signPk = signPkInG1
  coreVerifyPk = coreVerifyPkInG1
  pairingChkNAggrPk = pairingChkNAggrPkInG1

instance IsCurve 'G2 where
  skToPkPoint = skToPkInG2
  signPk = signPkInG2
  coreVerifyPk = coreVerifyPkInG2
  pairingChkNAggrPk = pairingChkNAggrPkInG2

-- | Class for operations on points.
type IsPoint :: PointKind -> Constraint
class (KnownNat (SerializedSize p), KnownNat (CompressedSize p)) => IsPoint p where
  toAffine :: Point p -> IO (Affine p)
  fromAffine :: Affine p -> IO (Point p)
  affSerialize :: Affine p -> IO (SizedByteArray (SerializedSize p) Bytes)
  affCompress :: Affine p -> IO (SizedByteArray (CompressedSize p) Bytes)
  uncompress
    :: ByteArrayAccess ba
    => SizedByteArray (CompressedSize p) ba
    -> IO (Either BlstError (Affine p))
  addOrDoubleAffine :: Point p -> Affine p -> IO (Point p)
  deserialize
    :: ByteArrayAccess ba
    => SizedByteArray (SerializedSize p) ba
    -> IO (Either BlstError (Affine p))

instance IsPoint 'P1 where
  toAffine = p1ToAffine
  fromAffine = p1FromAffine
  affSerialize = p1AffSerialize
  affCompress = p1AffCompress
  uncompress = p1Uncompress
  addOrDoubleAffine = p1AddOrDoubleAffine
  deserialize = p1Deserialize

instance IsPoint 'P2 where
  toAffine = p2ToAffine
  fromAffine = p2FromAffine
  affSerialize = p2AffSerialize
  affCompress = p2AffCompress
  uncompress = p2Uncompress
  addOrDoubleAffine = p2AddOrDoubleAffine
  deserialize = p2Deserialize

-- | Class for encoding/hashing to curve.
type ToCurve :: EncodeMethod -> Curve -> Constraint
class (IsCurve c, Demote meth) => ToCurve meth c where
  toCurve
    :: (ByteArrayAccess ba, ByteArrayAccess ba2)
    => ba -> Maybe ba2 -> IO (Point (CurveToMsgPoint c))

-- Note: it might seem this is backwards, but it's not.
instance ToCurve 'Encode 'G1 where toCurve = encodeToG2
instance ToCurve 'Encode 'G2 where toCurve = encodeToG1
instance ToCurve 'Hash 'G1 where toCurve = hashToG2
instance ToCurve 'Hash 'G2 where toCurve = hashToG1
