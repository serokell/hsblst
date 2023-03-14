-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

#include <blst.h>

{-# OPTIONS_HADDOCK not-home #-}

-- | Lower-level bindings. Functions starting with @blst_@ are raw c2hs
-- bindings. Others are slightly higher level wrappers around those bindings.
--
-- See
-- <https://github.com/supranational/blst/tree/f791f7a465cda8ecda74df0a60778331dde40809#introductory-tutorial>
-- for a more comprehensive explanation of the functions declared here.
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

-- | Generate secret key from bytes. Input must be at least 32 bytes long.
keygen :: ByteArrayAccess ba => ba -> IO Scalar
keygen bytes = fmap Scalar $
  AS.create $ \ptr ->
  withByteArray bytes $ \bytes' ->
    -- void blst_keygen(blst_scalar *out_SK, const byte *IKM, size_t IKM_len,
    --                  const byte *info DEFNULL, size_t info_len DEFNULL);
    {# call blst_keygen #} ptr bytes' (fromIntegral $ length bytes) nullPtr 0

-- | Convert scalar to a point in G1.
skToPkInG1 :: Scalar -> IO (Point 'P1)
skToPkInG1 (Scalar sk) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sk $ \sk' ->
    -- void blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    {# call blst_sk_to_pk_in_g1 #} ptr sk'

-- | Convert scalar to a P2 point in G2.
skToPkInG2 :: Scalar -> IO (Point 'P2)
skToPkInG2 (Scalar sk) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sk $ \sk' ->
    -- void blst_sk_to_pk_in_g2(blst_p2 *out_pk, const blst_scalar *SK);
    {# call blst_sk_to_pk_in_g2 #} ptr sk'

-- | Sign a message point in G1.
signPkInG1 :: Point 'P2 -> Scalar -> IO (Point 'P2)
signPkInG1 (Point p2) (Scalar sc) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sc $ \sc' ->
  withByteArray p2 $ \p2' ->
    -- void blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash,
    --                                           const blst_scalar *SK);
    {# call blst_sign_pk_in_g1 #} ptr p2' sc'

-- | Sign a message point in G2.
signPkInG2 :: Point 'P1 -> Scalar -> IO (Point 'P1)
signPkInG2 (Point p1) (Scalar sc) = fmap Point $
  AS.create $ \ptr ->
  withByteArray sc $ \sc' ->
  withByteArray p1 $ \p1' ->
    -- void blst_sign_pk_in_g2(blst_p1 *out_sig, const blst_p1 *hash,
    --                                           const blst_scalar *SK);
    {# call blst_sign_pk_in_g2 #} ptr p1' sc'

-- | Encode bytes to a point in G1.
encodeToG1 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P1)
encodeToG1 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- void blst_encode_to_g1(blst_p1 *out,
    --                        const byte *msg, size_t msg_len,
    --                        const byte *DST DEFNULL, size_t DST_len DEFNULL,
    --                        const byte *aug DEFNULL, size_t aug_len DEFNULL);
    {# call blst_encode_to_g1 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- | Hash bytes to a point in G1.
hashToG1 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P1)
hashToG1 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- void blst_hash_to_g1(blst_p1 *out,
    --                      const byte *msg, size_t msg_len,
    --                      const byte *DST DEFNULL, size_t DST_len DEFNULL,
    --                      const byte *aug DEFNULL, size_t aug_len DEFNULL);
    {# call blst_hash_to_g1 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- | Encode bytes to a point in G2.
encodeToG2 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P2)
encodeToG2 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- void blst_encode_to_g2(blst_p2 *out,
    --                        const byte *msg, size_t msg_len,
    --                        const byte *DST DEFNULL, size_t DST_len DEFNULL,
    --                        const byte *aug DEFNULL, size_t aug_len DEFNULL);
    {# call blst_encode_to_g2 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- | Hash bytes to a point in G2.
hashToG2 :: (ByteArrayAccess ba, ByteArrayAccess ba2) => ba -> Maybe ba2 -> IO (Point 'P2)
hashToG2 msg dst = fmap Point $
  AS.create $ \ptr ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- void blst_hash_to_g2(blst_p2 *out,
    --                      const byte *msg, size_t msg_len,
    --                      const byte *DST DEFNULL, size_t DST_len DEFNULL,
    --                      const byte *aug DEFNULL, size_t aug_len DEFNULL);
    {# call blst_hash_to_g2 #} ptr msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst) nullPtr 0

-- | Core signature verification function in G1.
coreVerifyPkInG1
  :: (ByteArrayAccess ba, ByteArrayAccess ba2)
  => Affine 'P1 -- ^ Public key
  -> Affine 'P2 -- ^ Signature
  -> EncodeMethod -- ^ Was message encoded or hashed to the curve
  -> ba -- ^ Message
  -> Maybe ba2 -- ^ Optional domain separation tag
  -> IO BlstError
coreVerifyPkInG1 (Affine pk) (Affine sig) hoe msg dst = fmap (toEnum . fromIntegral) $
  withByteArray pk $ \pk' ->
  withByteArray sig $ \sig' ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- BLST_ERROR blst_core_verify_pk_in_g1(const blst_p1_affine *pk,
    --                                      const blst_p2_affine *signature,
    --                                      bool hash_or_encode,
    --                                      const byte *msg, size_t msg_len,
    --                                      const byte *DST DEFNULL,
    --                                      size_t DST_len DEFNULL,
    --                                      const byte *aug DEFNULL,
    --                                      size_t aug_len DEFNULL);
    {# call blst_core_verify_pk_in_g1 #} pk' sig' (fromIntegral $ fromEnum hoe)
      msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst)
      nullPtr 0

-- | Core signature verification function in G2.
coreVerifyPkInG2
  :: (ByteArrayAccess ba, ByteArrayAccess ba2)
  => Affine 'P2 -- ^ Public key
  -> Affine 'P1 -- ^ Signature
  -> EncodeMethod -- ^ Was message encoded or hashed to the curve
  -> ba -- ^ Message
  -> Maybe ba2 -- ^ Optional domain separation tag
  -> IO BlstError
coreVerifyPkInG2 (Affine pk) (Affine sig) hoe msg dst = fmap (toEnum . fromIntegral) $
  withByteArray pk $ \pk' ->
  withByteArray sig $ \sig' ->
  withByteArray msg $ \msg' ->
  maybe ($ nullPtr) withByteArray dst $ \dst' ->
    -- BLST_ERROR blst_core_verify_pk_in_g2(const blst_p2_affine *pk,
    --                                      const blst_p1_affine *signature,
    --                                      bool hash_or_encode,
    --                                      const byte *msg, size_t msg_len,
    --                                      const byte *DST DEFNULL,
    --                                      size_t DST_len DEFNULL,
    --                                      const byte *aug DEFNULL,
    --                                      size_t aug_len DEFNULL);
    {# call blst_core_verify_pk_in_g2 #} pk' sig' (fromIntegral $ fromEnum hoe)
      msg' (fromIntegral $ length msg)
      dst' (maybe 0 (fromIntegral . length) dst)
      nullPtr 0

-- | Convert point to affine point in G1.
p1ToAffine :: Point 'P1 -> IO (Affine 'P1)
p1ToAffine (Point p1) = fmap Affine $
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    -- void blst_p1_to_affine(blst_p1_affine *out, const blst_p1 *in);
    {# call blst_p1_to_affine #} ptr p1'

-- | Convert point to affine point in G2.
p2ToAffine :: Point 'P2 -> IO (Affine 'P2)
p2ToAffine (Point p2) = fmap Affine $
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    -- void blst_p2_to_affine(blst_p2_affine *out, const blst_p2 *in);
    {# call blst_p2_to_affine #} ptr p2'

-- | Serialize affine G1 point.
p1AffSerialize :: Affine 'P1 -> IO (SizedByteArray P1SerializeSize Bytes)
p1AffSerialize (Affine p1) =
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    -- void blst_p1_affine_serialize(byte out[96], const blst_p1_affine *in);
    {# call blst_p1_affine_serialize #} ptr p1'

-- | Serialize and compress affine G1 point.
p1AffCompress :: Affine 'P1 -> IO (SizedByteArray P1CompressSize Bytes)
p1AffCompress (Affine p1) =
  AS.create $ \ptr ->
  withByteArray p1 $ \p1' ->
    -- void blst_p1_affine_compress(byte out[48], const blst_p1_affine *in);
    {# call blst_p1_affine_compress #} ptr p1'

-- | Deserialize affine G1 point.
p1Deserialize
  :: ByteArrayAccess ba
  => SizedByteArray P1SerializeSize ba
  -> IO (Either BlstError (Affine 'P1))
p1Deserialize bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      -- BLST_ERROR blst_p1_deserialize(blst_p1_affine *out, const byte in[96]);
      res <- {# call blst_p1_deserialize #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- | Deserialize and decompress affine G1 point.
p1Uncompress
  :: ByteArrayAccess ba
  => SizedByteArray P1CompressSize ba
  -> IO (Either BlstError (Affine 'P1))
p1Uncompress bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      -- BLST_ERROR blst_p1_uncompress(blst_p1_affine *out, const byte in[48]);
      res <- {# call blst_p1_uncompress #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- | Serialize affine G2 point.
p2AffSerialize :: Affine 'P2 -> IO (SizedByteArray P2SerializeSize Bytes)
p2AffSerialize (Affine p2) =
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    -- void blst_p2_affine_serialize(byte out[192], const blst_p2_affine *in);
    {# call blst_p2_affine_serialize #} ptr p2'

-- | Serialize and compress affine G2 point.
p2AffCompress :: Affine 'P2 -> IO (SizedByteArray P2CompressSize Bytes)
p2AffCompress (Affine p2) =
  AS.create $ \ptr ->
  withByteArray p2 $ \p2' ->
    -- void blst_p2_affine_compress(byte out[96], const blst_p2_affine *in);
    {# call blst_p2_affine_compress #} ptr p2'

-- | Deserialize affine G2 point.
p2Deserialize
  :: ByteArrayAccess ba
  => SizedByteArray P2SerializeSize ba
  -> IO (Either BlstError (Affine 'P2))
p2Deserialize bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      -- BLST_ERROR blst_p2_deserialize(blst_p2_affine *out, const byte in[192]);
      res <- {# call blst_p2_deserialize #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- | Deserialize and decompress affine G2 point.
p2Uncompress
  :: ByteArrayAccess ba
  => SizedByteArray P2CompressSize ba
  -> IO (Either BlstError (Affine 'P2))
p2Uncompress bs = do
  fmap (Right . Affine) $
    AS.create $ \ptr ->
    withByteArray bs $ \bs' -> do
      -- BLST_ERROR blst_p2_uncompress(blst_p2_affine *out, const byte in[96]);
      res <- {# call blst_p2_uncompress #} ptr bs'
      let res' = toEnum $ fromIntegral res
      case res' of
        BlstSuccess -> pure ()
        x -> throwIO x
  `catch` \(x :: BlstError) -> pure $ Left x

-- | Get scalar bytes in little endian order.
lendianFromScalar :: Scalar -> IO (SizedByteArray SkSerializeSize ScrubbedBytes)
lendianFromScalar (Scalar sc) =
  AS.create $ \out ->
  withByteArray sc $ \sc' ->
  -- void blst_lendian_from_scalar(byte out[32], const blst_scalar *a);
  {# call blst_lendian_from_scalar #} out sc'

-- | Build scalar from bytes in little endian order.
scalarFromLendian :: ByteArrayAccess ba => SizedByteArray SkSerializeSize ba -> IO Scalar
scalarFromLendian bs = fmap Scalar $
  AS.create $ \out ->
  withByteArray bs $ \bs' ->
  -- void blst_scalar_from_lendian(blst_scalar *out, const byte a[32]);
  {# call blst_scalar_from_lendian #} out bs'

-- | Add affine point to point in G1.
p1AddOrDoubleAffine :: Point 'P1 -> Affine 'P1 -> IO (Point 'P1)
p1AddOrDoubleAffine (Point a) (Affine b) = fmap Point $
  AS.create $ \out ->
  withByteArray a $ \a' ->
  withByteArray b $ \b' ->
  -- void blst_p1_add_or_double_affine(blst_p1 *out, const blst_p1 *a,
  --                                                 const blst_p1_affine *b);
  {# call blst_p1_add_or_double_affine #} out a' b'

-- | Add affine point to point in G2.
p2AddOrDoubleAffine :: Point 'P2 -> Affine 'P2 -> IO (Point 'P2)
p2AddOrDoubleAffine (Point a) (Affine b) = fmap Point $
  AS.create $ \out ->
  withByteArray a $ \a' ->
  withByteArray b $ \b' ->
  -- void blst_p2_add_or_double_affine(blst_p2 *out, const blst_p2 *a,
  --                                                 const blst_p2_affine *b);
  {# call blst_p2_add_or_double_affine #} out a' b'

-- | Convert affine point to point in G1.
p1FromAffine :: Affine 'P1 -> IO (Point 'P1)
p1FromAffine (Affine aff) = fmap Point $
  AS.create $ \out ->
  withByteArray aff $ \aff' ->
  -- void blst_p1_from_affine(blst_p1 *out, const blst_p1_affine *in);
  {# call blst_p1_from_affine #} out aff'

-- | Convert affine point to point in G2.
p2FromAffine :: Affine 'P2 -> IO (Point 'P2)
p2FromAffine (Affine aff) = fmap Point $
  AS.create $ \out ->
  withByteArray aff $ \aff' ->
  -- void blst_p2_from_affine(blst_p2 *out, const blst_p2_affine *in);
  {# call blst_p2_from_affine #} out aff'

-- | Check aggregate signature in G1.
pairingChkNAggrPkInG1
  :: ByteArrayAccess ba
  => PairingCtx -- ^ Pairing context. Use 'pairingInit' to create.
  -> Affine 'P1 -- ^ Public key
  -> Bool -- ^ Check public key group?
  -> Maybe (Affine 'P2)
  -- ^ Signature. Only the first call per pairing context specifies the
  -- signature, all consequent calls for the same context should use 'Nothing'
  -- here.
  -> Bool -- ^ Check signature group?
  -> ba -- ^ Message
  -> IO BlstError
pairingChkNAggrPkInG1 (PairingCtx ctx) (Affine pk) pk_gpck sig sig_gpck msg =
  fmap (toEnum . fromIntegral) $
  withByteArray ctx $ \ctx' ->
  withByteArray pk $ \pk' ->
  maybe ($ nullPtr) (withByteArray . unAffine) sig $ \sig' ->
  withByteArray msg $ \msg' ->
  -- BLST_ERROR blst_pairing_chk_n_aggr_pk_in_g1(blst_pairing *ctx,
  --                                             const blst_p1_affine *PK,
  --                                             bool pk_grpchk,
  --                                             const blst_p2_affine *signature,
  --                                             bool sig_grpchk,
  --                                             const byte *msg, size_t msg_len,
  --                                             const byte *aug DEFNULL,
  --                                             size_t aug_len DEFNULL);
  {# call blst_pairing_chk_n_aggr_pk_in_g1 #} ctx' pk' (fromBool pk_gpck) sig'
    (fromBool sig_gpck) msg' (fromIntegral $ length msg) nullPtr 0

-- | Check aggregate signature in G2.
pairingChkNAggrPkInG2
  :: ByteArrayAccess ba
  => PairingCtx -- ^ Pairing context. Use 'pairingInit' to create.
  -> Affine 'P2 -- ^ Public key
  -> Bool -- ^ Check public key group?
  -> Maybe (Affine 'P1)
  -- ^ Signature. Only the first call per pairing context specifies the
  -- signature, all consequent calls for the same context should use 'Nothing'
  -- here.
  -> Bool -- ^ Check signature group?
  -> ba -- ^ Message
  -> IO BlstError
pairingChkNAggrPkInG2 (PairingCtx ctx) (Affine pk) pk_gpck sig sig_gpck msg =
  fmap (toEnum . fromIntegral) $
  withByteArray ctx $ \ctx' ->
  withByteArray pk $ \pk' ->
  maybe ($ nullPtr) (withByteArray . unAffine) sig $ \sig' ->
  withByteArray msg $ \msg' ->
  -- BLST_ERROR blst_pairing_chk_n_aggr_pk_in_g2(blst_pairing *ctx,
  --                                             const blst_p2_affine *PK,
  --                                             bool pk_grpchk,
  --                                             const blst_p1_affine *signature,
  --                                             bool sig_grpchk,
  --                                             const byte *msg, size_t msg_len,
  --                                             const byte *aug DEFNULL,
  --                                             size_t aug_len DEFNULL);
  {# call blst_pairing_chk_n_aggr_pk_in_g2 #} ctx' pk' (fromBool pk_gpck) sig'
    (fromBool sig_gpck) msg' (fromIntegral $ length msg) nullPtr 0

-- | Make new pairing context.
pairingInit :: ByteArrayAccess ba => EncodeMethod -> Maybe ba -> IO PairingCtx
pairingInit hoe dst = do
  sz <- {# call blst_pairing_sizeof #}
  fmap PairingCtx $ BA.create (fromIntegral sz) $ \out ->
    maybe ($ nullPtr) withByteArray dst $ \dst' ->
      -- void blst_pairing_init(blst_pairing *new_ctx, bool hash_or_encode,
      --                        const byte *DST DEFNULL, size_t DST_len DEFNULL);
      {# call blst_pairing_init #} out (fromIntegral $ fromEnum hoe)
        dst' (maybe 0 (fromIntegral . length) dst)

-- | Commit pairing context.
pairingCommit :: PairingCtx -> IO ()
pairingCommit (PairingCtx ctx) =
  withByteArray ctx $ \ctx' ->
    -- void blst_pairing_commit(blst_pairing *ctx);
    {# call blst_pairing_commit #} ctx'

-- | Verify pairing context.
pairingFinalVerify :: PairingCtx -> IO Bool
pairingFinalVerify (PairingCtx ctx) = fmap toBool $
  withByteArray ctx $ \ctx' ->
    -- bool blst_pairing_finalverify(const blst_pairing *ctx,
    --                               const blst_fp12 *gtsig DEFNULL);
    {# call blst_pairing_finalverify #} ctx' nullPtr
