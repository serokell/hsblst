-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

-- | Test for interoperability with Tezos.
module Test.BLST.Tezos
  ( test_tezos
  ) where

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, (@?=))

import Crypto.BLST qualified as BLST

import Test.BLST.Util

test_tezos :: TestTree
test_tezos = testCase "Congruity with tezos" $ do
  let sk_ser =
        "98369b5e877a68809b77eaf3c268c5b4\
        \795faa08128ffad75e6be9bf7238b50f"
      pk_exp_ser =
        "8b3b4aec31cbf873759c367f42a44da7\
        \b755a56dbf4e86e2db545073eeabb547\
        \c70a405e998ee152d2d92d2868eb3633"
      sk = BLST.deserializeSk $ fromHex sk_ser
      pk = BLST.skToPk sk :: BLST.PublicKey 'BLST.G1
      pk_exp = BLST.decompressPk $ fromHex pk_exp_ser
  Right pk @?= pk_exp
  toHex (BLST.compressPk pk) @?= pk_exp_ser
  toHex (BLST.serializeSk sk) @?= sk_ser
