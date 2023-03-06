-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

-- | Test for interoperability with Tezos.
module Test.BLST.Tezos
  ( test_tezos
  ) where

import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, (@?=))

import Crypto.BLST qualified as BLST

import Test.BLST.Util

test_tezos :: TestTree
test_tezos = testCase "Congruity with tezos" $ do
  let sk_ser =
        "79cc407e6917b5673a1f6966c23c9e15\
        \d257e5ab46cfe7b9b2f64200f2b2843e"
      pk_exp_ser =
        "b6cf94b6a59d102044d1ff16ebe3eccc\
        \5cd554965bb66ac80fb2728c18715817\
        \e185fb5ac9437908c9e609a742610177"
      signature =
        "8b7cd0689ad2eb42de97258d34db9eb3\
        \8585ec1b1f5be3c4ff580fb3147e33f6\
        \7246cf192b16ded6e9194720a11bf59d\
        \179cea087ef8c03c227ce10ce78bb1c7\
        \4c592e148d9ad0e1cf361b47e1235628\
        \fcf54ccbf6e8bda31f177107377dccda"
      sk = BLST.deserializeSk $ fromHex sk_ser
      pk = BLST.skToPk sk :: BLST.PublicKey 'BLST.G1
      pk_exp = BLST.decompressPk $ fromHex pk_exp_ser
      bytes = "\x12\x34\x56" :: ByteString
      sig = BLST.sign sk msg dst
      sig_ser :: BLST.Signature 'BLST.G1 'BLST.Hash =
        either (error "failed to decompress") id $ BLST.decompressSignature $ fromHex signature
      dst = Just ("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_" :: ByteString)
      msg = convert (BLST.compressPk pk) <> bytes
  Right pk @?= pk_exp
  toHex (BLST.compressPk pk) @?= pk_exp_ser
  toHex (BLST.serializeSk sk) @?= sk_ser
  BLST.verify sig_ser pk msg dst @?= BLST.BlstSuccess
  sig @?= sig_ser
