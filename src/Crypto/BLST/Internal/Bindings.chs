-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

#include <blst.h>

{-# OPTIONS_HADDOCK not-home #-}

-- | Lower-level bindings
module Crypto.BLST.Internal.Bindings
  ( module Crypto.BLST.Internal.Bindings
  , module Crypto.BLST.Internal.Bindings.Types
  ) where

import Prelude hiding (length)

import Control.Exception (Exception, catch, throwIO)
import Data.ByteArray (ByteArrayAccess(..), Bytes, ScrubbedBytes)
import Data.ByteArray qualified as BA
import Data.ByteArray.Sized (SizedByteArray)
import Data.ByteArray.Sized qualified as AS
import Foreign.Marshal.Utils (fromBool, toBool)
import Foreign.Ptr (nullPtr)

import Crypto.BLST.Internal.Bindings.Types

type instance SizeOf (Point 'P1) = {# sizeof blst_p1 #}
type instance SizeOf (Point 'P2) = {# sizeof blst_p2 #}

type instance SizeOf (Affine 'P1) = {# sizeof blst_p1_affine #}
type instance SizeOf (Affine 'P2) = {# sizeof blst_p2_affine #}

type instance SizeOf Scalar = {# sizeof blst_scalar #}

-- | Possible C return values.
{# enum BLST_ERROR as BlstError {underscoreToCase} #}

deriving stock instance Eq BlstError
deriving stock instance Bounded BlstError
deriving stock instance Show BlstError

instance Exception BlstError

-- void blst_keygen(blst_scalar *out_SK, const byte *IKM, size_t IKM_len,
--                  const byte *info DEFNULL, size_t info_len DEFNULL);
keygen :: ByteArrayAccess ba => ba -> IO Scalar
keygen bytes = fmap Scalar $
  AS.create $ \ptr ->
  withByteArray bytes $ \bytes' ->
    {# call blst_keygen #} ptr bytes' (fromIntegral $ length bytes) nullPtr 0

-- void blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
skToPkInG1 :: Scalar -> IO (Point 'P1)
skToPkInG1 (Scalar sk) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sk $ \sk' ->
    {# call blst_sk_to_pk_in_g1 #} ptr sk'

-- void blst_sk_to_pk_in_g2(blst_p2 *out_pk, const blst_scalar *SK);
skToPkInG2 :: Scalar -> IO (Point 'P2)
skToPkInG2 (Scalar sk) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sk $ \sk' ->
    {# call blst_sk_to_pk_in_g2 #} ptr sk'

-- void blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash,
--                                           const blst_scalar *SK);
signPkInG1 :: Point 'P2 -> Scalar -> IO (Point 'P2)
signPkInG1 (Point p2) (Scalar sc) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sc $ \sc' ->
  withByteArray p2 $ \p2' ->
    {# call blst_sign_pk_in_g1 #} ptr p2' sc'

-- void blst_sign_pk_in_g2(blst_p1 *out_sig, const blst_p1 *hash,
--                                           const blst_scalar *SK);
signPkInG2 :: Point 'P1 -> Scalar -> IO (Point 'P1)
signPkInG2 (Point p1) (Scalar sc) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sc $ \sc' ->
  withByteArray p1 $ \p1' ->
    {# call blst_sign_pk_in_g2 #} ptr p1' sc'

-- void blst_encode_to_g1(blst_p1 *out,
--                        const byte *msg, size_t msg_len,
--                        const byte *DST DEFNULL, size_t DST_len DEFNULL,
--                        const byte *aug DEFNULL, size_t aug_len DEFNULL);
encodeToG1 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P1)
encodeToG1 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_encode_to_g1 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- void blst_hash_to_g1(blst_p1 *out,
--                      const byte *msg, size_t msg_len,
--                      const byte *DST DEFNULL, size_t DST_len DEFNULL,
--                      const byte *aug DEFNULL, size_t aug_len DEFNULL);
hashToG1 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P1)
hashToG1 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_hash_to_g1 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- void blst_encode_to_g2(blst_p2 *out,
--                        const byte *msg, size_t msg_len,
--                        const byte *DST DEFNULL, size_t DST_len DEFNULL,
--                        const byte *aug DEFNULL, size_t aug_len DEFNULL);
encodeToG2 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P2)
encodeToG2 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_encode_to_g2 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- void blst_hash_to_g2(blst_p2 *out,
--                      const byte *msg, size_t msg_len,
--                      const byte *DST DEFNULL, size_t DST_len DEFNULL,
--                      const byte *aug DEFNULL, size_t aug_len DEFNULL);
hashToG2 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P2)
hashToG2 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_hash_to_g2 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- BLST_ERROR blst_core_verify_pk_in_g1(const blst_p1_affine *pk,
--                                      const blst_p2_affine *signature,
--                                      bool hash_or_encode,
--                                      const byte *msg, size_t msg_len,
--                                      const byte *DST DEFNULL,
--                                      size_t DST_len DEFNULL,
--                                      const byte *aug DEFNULL,
--                                      size_t aug_len DEFNULL);
coreVerifyPkInG1
  :: (ByteArrayAccess ba, ByteArrayAccess ba2)
  => Affine 'P1
  -> Affine 'P2
  -> EncodeMethod
  -> ba
  -> Maybe ba2
  -> IO BlstError
coreVerifyPkInG1 (Affine pk) (Affine sig) hoe msg dst = fmap (toEnum . fromIntegral) $
  withByteArray pk $ \pk' ->
  withByteArray sig $ \sig' ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_core_verify_pk_in_g1 #} pk' sig' (fromIntegral $ fromEnum hoe)
      msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst)
      nullPtr 0

-- BLST_ERROR blst_core_verify_pk_in_g2(const blst_p2_affine *pk,
--                                      const blst_p1_affine *signature,
--                                      bool hash_or_encode,
--                                      const byte *msg, size_t msg_len,
--                                      const byte *DST DEFNULL,
--                                      size_t DST_len DEFNULL,
--                                      const byte *aug DEFNULL,
--                                      size_t aug_len DEFNULL);
coreVerifyPkInG2
  :: (ByteArrayAccess ba, ByteArrayAccess ba2)
  => Affine 'P2
  -> Affine 'P1
  -> EncodeMethod
  -> ba
  -> Maybe ba2
  -> IO BlstError
coreVerifyPkInG2 (Affine pk) (Affine sig) hoe msg dst = fmap (toEnum . fromIntegral) $
  withByteArray pk $ \pk' ->
  withByteArray sig $ \sig' ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    {# call blst_core_verify_pk_in_g2 #} pk' sig' (fromIntegral $ fromEnum hoe)
      msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst)
      nullPtr 0

-- void blst_p1_to_affine(blst_p1_affine *out, const blst_p1 *in);
p1ToAffine :: Point 'P1 -> IO (Affine 'P1)
p1ToAffine (Point p1) = fmap Affine $
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    {# call blst_p1_to_affine #} ptr p1'

-- void blst_p2_to_affine(blst_p2_affine *out, const blst_p2 *in);
p2ToAffine :: Point 'P2 -> IO (Affine 'P2)
p2ToAffine (Point p2) = fmap Affine $
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    {# call blst_p2_to_affine #} ptr p2'

-- void blst_p1_affine_serialize(byte out[96], const blst_p1_affine *in);
p1AffSerialize :: Affine 'P1 -> IO (SizedByteArray P1SerializeSize Bytes)
p1AffSerialize (Affine p1) =
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    {# call blst_p1_affine_serialize #} ptr p1'

-- void blst_p1_affine_compress(byte out[48], const blst_p1_affine *in);
p1AffCompress :: Affine 'P1 -> IO (SizedByteArray P1CompressSize Bytes)
p1AffCompress (Affine p1) =
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    {# call blst_p1_affine_compress #} ptr p1'

-- BLST_ERROR blst_p1_deserialize(blst_p1_affine *out, const byte in[96]);
p1Deserialize
  :: ByteArrayAccess ba
  => SizedByteArray P1SerializeSize ba
  -> IO (Either BlstError (Affine 'P1))
p1Deserialize bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      res <- {# call blst_p1_deserialize #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- BLST_ERROR blst_p1_uncompress(blst_p1_affine *out, const byte in[48]);
p1Uncompress
  :: ByteArrayAccess ba
  => SizedByteArray P1CompressSize ba
  -> IO (Either BlstError (Affine 'P1))
p1Uncompress bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      res <- {# call blst_p1_uncompress #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- void blst_p2_affine_serialize(byte out[192], const blst_p2_affine *in);
p2AffSerialize :: Affine 'P2 -> IO (SizedByteArray P2SerializeSize Bytes)
p2AffSerialize (Affine p2) =
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    {# call blst_p2_affine_serialize #} ptr p2'

-- void blst_p2_affine_compress(byte out[96], const blst_p2_affine *in);
p2AffCompress :: Affine 'P2 -> IO (SizedByteArray P2CompressSize Bytes)
p2AffCompress (Affine p2) =
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    {# call blst_p2_affine_compress #} ptr p2'

-- BLST_ERROR blst_p2_deserialize(blst_p2_affine *out, const byte in[192]);
p2Deserialize
  :: ByteArrayAccess ba
  => SizedByteArray P2SerializeSize ba
  -> IO (Either BlstError (Affine 'P2))
p2Deserialize bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      res <- {# call blst_p2_deserialize #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- BLST_ERROR blst_p2_uncompress(blst_p2_affine *out, const byte in[96]);
p2Uncompress
  :: ByteArrayAccess ba
  => SizedByteArray P2CompressSize ba
  -> IO (Either BlstError (Affine 'P2))
p2Uncompress bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      res <- {# call blst_p2_uncompress #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- void blst_lendian_from_scalar(byte out[32], const blst_scalar *a);
lendianFromScalar :: Scalar -> IO (SizedByteArray SkSerializeSize ScrubbedBytes)
lendianFromScalar (Scalar sc) =
  AS.create $ \out ->
  withByteArray sc $ \sc' ->
  {# call blst_lendian_from_scalar #} out sc'

-- void blst_scalar_from_lendian(blst_scalar *out, const byte a[32]);
scalarFromLendian :: ByteArrayAccess ba => SizedByteArray SkSerializeSize ba -> IO Scalar
scalarFromLendian bs = fmap Scalar $
  AS.create $ \out ->
  withByteArray bs $ \bs' ->
  {# call blst_scalar_from_lendian #} out bs'

-- void blst_p1_add_or_double_affine(blst_p1 *out, const blst_p1 *a,
--                                                 const blst_p1_affine *b);
p1AddOrDoubleAffine :: Point 'P1 -> Affine 'P1 -> IO (Point 'P1)
p1AddOrDoubleAffine (Point a) (Affine b) = fmap Point $
  AS.create $ \out ->
  withByteArray a $ \a' ->
  withByteArray b $ \b' ->
  {# call blst_p1_add_or_double_affine #} out a' b'

-- void blst_p2_add_or_double_affine(blst_p2 *out, const blst_p2 *a,
--                                                 const blst_p2_affine *b);
p2AddOrDoubleAffine :: Point 'P2 -> Affine 'P2 -> IO (Point 'P2)
p2AddOrDoubleAffine (Point a) (Affine b) = fmap Point $
  AS.create $ \out ->
  withByteArray a $ \a' ->
  withByteArray b $ \b' ->
  {# call blst_p2_add_or_double_affine #} out a' b'

-- void blst_p1_from_affine(blst_p1 *out, const blst_p1_affine *in);
p1FromAffine :: Affine 'P1 -> IO (Point 'P1)
p1FromAffine (Affine aff) = fmap Point $
  AS.create $ \out ->
  withByteArray aff $ \aff' ->
  {# call blst_p1_from_affine #} out aff'

-- void blst_p2_from_affine(blst_p2 *out, const blst_p2_affine *in);
p2FromAffine :: Affine 'P2 -> IO (Point 'P2)
p2FromAffine (Affine aff) = fmap Point $
  AS.create $ \out ->
  withByteArray aff $ \aff' ->
  {# call blst_p2_from_affine #} out aff'

-- BLST_ERROR blst_pairing_chk_n_aggr_pk_in_g1(blst_pairing *ctx,
--                                             const blst_p1_affine *PK,
--                                             bool pk_grpchk,
--                                             const blst_p2_affine *signature,
--                                             bool sig_grpchk,
--                                             const byte *msg, size_t msg_len,
--                                             const byte *aug DEFNULL,
--                                             size_t aug_len DEFNULL);
pairingChkNAggrPkInG1
  :: ByteArrayAccess ba
  => PairingCtx
  -> Affine 'P1
  -> Bool
  -> Maybe (Affine 'P2)
  -> Bool
  -> ba
  -> IO BlstError
pairingChkNAggrPkInG1 (PairingCtx ctx) (Affine pk) pk_gpck sig sig_gpck msg =
  fmap (toEnum . fromIntegral) $
  withByteArray ctx $ \ctx' ->
  withByteArray pk $ \pk' ->
  maybe ($ nullPtr) (withByteArray . unAffine) sig $ \sig' ->
  withByteArray msg $ \msg' ->
  {# call blst_pairing_chk_n_aggr_pk_in_g1 #} ctx' pk' (fromBool pk_gpck) sig'
    (fromBool sig_gpck) msg' (fromIntegral $ length msg) nullPtr 0

-- BLST_ERROR blst_pairing_chk_n_aggr_pk_in_g2(blst_pairing *ctx,
--                                             const blst_p2_affine *PK,
--                                             bool pk_grpchk,
--                                             const blst_p1_affine *signature,
--                                             bool sig_grpchk,
--                                             const byte *msg, size_t msg_len,
--                                             const byte *aug DEFNULL,
--                                             size_t aug_len DEFNULL);
pairingChkNAggrPkInG2
  :: ByteArrayAccess ba
  => PairingCtx
  -> Affine 'P2
  -> Bool
  -> Maybe (Affine 'P1)
  -> Bool
  -> ba
  -> IO BlstError
pairingChkNAggrPkInG2 (PairingCtx ctx) (Affine pk) pk_gpck sig sig_gpck msg =
  fmap (toEnum . fromIntegral) $
  withByteArray ctx $ \ctx' ->
  withByteArray pk $ \pk' ->
  maybe ($ nullPtr) (withByteArray . unAffine) sig $ \sig' ->
  withByteArray msg $ \msg' ->
  {# call blst_pairing_chk_n_aggr_pk_in_g2 #} ctx' pk' (fromBool pk_gpck) sig'
    (fromBool sig_gpck) msg' (fromIntegral $ length msg) nullPtr 0

-- blst_pairing_initvoid blst_pairing_init(blst_pairing *new_ctx, bool hash_or_encode,
--                        const byte *DST DEFNULL, size_t DST_len DEFNULL);
pairingInit :: ByteArrayAccess ba => EncodeMethod -> Maybe ba -> IO PairingCtx
pairingInit hoe dst = do
  sz <- {# call blst_pairing_sizeof #}
  fmap PairingCtx $ BA.create (fromIntegral sz) $ \out ->
    maybe ($ nullPtr) withByteArray dst $ \dst' ->
      {# call blst_pairing_init #} out (fromIntegral $ fromEnum hoe)
        dst' (maybe 0 (fromIntegral . length) dst)

-- void blst_pairing_commit(blst_pairing *ctx);
pairingCommit :: PairingCtx -> IO ()
pairingCommit (PairingCtx ctx) =
  withByteArray ctx $ \ctx' ->
    {# call blst_pairing_commit #} ctx'

-- bool blst_pairing_finalverify(const blst_pairing *ctx,
--                               const blst_fp12 *gtsig DEFNULL);
pairingFinalVerify :: PairingCtx -> IO Bool
pairingFinalVerify (PairingCtx ctx) = fmap toBool $
  withByteArray ctx $ \ctx' ->
    {# call blst_pairing_finalverify #} ctx' nullPtr
