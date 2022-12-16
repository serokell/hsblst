-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

module Test.BLST.Bindings
  ( test_keygen
  , test_skToPkInG1
  , test_skToPkInG2
  , test_signPkInG1
  , test_signPkInG2
  , test_encodeToG1
  , test_hashToG1
  , test_encodeToG2
  , test_hashToG2
  , test_coreVerifyPkInG1
  , test_coreVerifyPkInG2
  , test_p1ToAffine
  , test_p2ToAffine
  , test_p1AffSerialize
  , test_p1Deserialize
  , test_p2AffSerialize
  , test_p2Deserialize
  , test_p1AffCompress
  , test_p1Uncompress
  , test_p2AffCompress
  , test_p2Uncompress
  , test_lendianFromScalar
  , test_scalarFromLendian
  ) where

import Data.ByteArray (Bytes)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase, (@?=))

import Crypto.BLST.Internal.Bindings qualified as B

import Test.BLST.Fixtures
import Test.BLST.Util

noDST :: Maybe Bytes
noDST = Nothing

test_keygen :: TestTree
test_keygen = testCase "keygen" $ do
  key <- B.keygen seed
  key @?= expectedKey

test_skToPkInG1 :: TestTree
test_skToPkInG1 = testCase "skToPkInG1" $ do
  pk1 <- B.skToPkInG1 expectedKey
  pk1 @?= expectedPk1

test_skToPkInG2 :: TestTree
test_skToPkInG2 = testCase "skToPkInG2" $ do
  pk2 <- B.skToPkInG2 expectedKey
  pk2 @?= expectedPk2

test_signPkInG1 :: TestTree
test_signPkInG1 = testCase "signPkInG1" $ do
  x <- B.signPkInG1 expectedHash2 expectedKey
  x @?= expectedSignHash1
  y <- B.signPkInG1 expectedEnc2 expectedKey
  y @?= expectedSignEnc1

test_signPkInG2 :: TestTree
test_signPkInG2 = testCase "signPkInG2" $ do
  x <- B.signPkInG2 expectedHash1 expectedKey
  x @?= expectedSignHash2
  y <- B.signPkInG2 expectedEnc1 expectedKey
  y @?= expectedSignEnc2

test_encodeToG1 :: TestTree
test_encodeToG1 = testCase "encodeToG1" $ do
  x <- B.encodeToG1 msg noDST
  x @?= expectedEnc1

test_hashToG1 :: TestTree
test_hashToG1 = testCase "hashToG1" $ do
  x <- B.hashToG1 msg noDST
  x @?= expectedHash1

test_encodeToG2 :: TestTree
test_encodeToG2 = testCase "encodeToG2" $ do
  x <- B.encodeToG2 msg noDST
  x @?= expectedEnc2

test_hashToG2 :: TestTree
test_hashToG2 = testCase "hashToG2" $ do
  x <- B.hashToG2 msg noDST
  x @?= expectedHash2

test_coreVerifyPkInG1 :: TestTree
test_coreVerifyPkInG1 = testCase "coreVerifyPkInG1" $ do
  r1 <- B.coreVerifyPkInG1 expectedAffPk1 expectedAffSignHash1 B.Hash msg noDST
  r1 @?= B.BlstSuccess
  r2 <- B.coreVerifyPkInG1 expectedAffPk1 expectedAffSignEnc1 B.Encode msg noDST
  r2 @?= B.BlstSuccess
  -- failing cases
  r3 <- B.coreVerifyPkInG1 expectedAffPk1 expectedAffSignHash1 B.Encode msg noDST
  r3 @?= B.BlstVerifyFail
  r4 <- B.coreVerifyPkInG1 expectedAffPk1 expectedAffSignEnc1 B.Hash msg noDST
  r4 @?= B.BlstVerifyFail

test_coreVerifyPkInG2 :: TestTree
test_coreVerifyPkInG2 = testCase "coreVerifyPkInG2" $ do
  r1 <- B.coreVerifyPkInG2 expectedAffPk2 expectedAffSignHash2 B.Hash msg noDST
  r1 @?= B.BlstSuccess
  r2 <- B.coreVerifyPkInG2 expectedAffPk2 expectedAffSignEnc2 B.Encode msg noDST
  r2 @?= B.BlstSuccess
  -- failing cases
  r3 <- B.coreVerifyPkInG2 expectedAffPk2 expectedAffSignHash2 B.Encode msg noDST
  r3 @?= B.BlstVerifyFail
  r4 <- B.coreVerifyPkInG2 expectedAffPk2 expectedAffSignEnc2 B.Hash msg noDST
  r4 @?= B.BlstVerifyFail

test_p1ToAffine :: TestTree
test_p1ToAffine = testCase "p1ToAffine" $ do
  x <- B.p1ToAffine expectedPk1
  x @?= expectedAffPk1
  y <- B.p1ToAffine expectedSignEnc2
  y @?= expectedAffSignEnc2
  z <- B.p1ToAffine expectedSignHash2
  z @?= expectedAffSignHash2

test_p2ToAffine :: TestTree
test_p2ToAffine = testCase "p2ToAffine" $ do
  x <- B.p2ToAffine expectedPk2
  x @?= expectedAffPk2
  y <- B.p2ToAffine expectedSignEnc1
  y @?= expectedAffSignEnc1
  z <- B.p2ToAffine expectedSignHash1
  z @?= expectedAffSignHash1

test_p1AffSerialize :: TestTree
test_p1AffSerialize = testCase "p1AffSerialize" $ do
  x <- B.p1AffSerialize expectedAffPk1
  x @?= expectedSer1

test_p1Deserialize :: TestTree
test_p1Deserialize = testCase "p1Deserialize" $ do
  x <- B.p1Deserialize expectedSer1
  x @?= Right expectedAffPk1

test_p2AffSerialize :: TestTree
test_p2AffSerialize = testCase "p2AffSerialize" $ do
  x <- B.p2AffSerialize expectedAffPk2
  x @?= expectedSer2

test_p2Deserialize :: TestTree
test_p2Deserialize = testCase "p2Deserialize" $ do
  x <- B.p2Deserialize expectedSer2
  x @?= Right expectedAffPk2

test_p1AffCompress :: TestTree
test_p1AffCompress = testCase "p1AffCompress" $ do
  x <- B.p1AffCompress expectedAffPk1
  toHex x @?= expectedComp1

test_p1Uncompress :: TestTree
test_p1Uncompress = testCase "p1Uncompress" $ do
  x <- B.p1Uncompress $ fromHex expectedComp1
  x @?= Right expectedAffPk1

test_p2AffCompress :: TestTree
test_p2AffCompress = testCase "p2AffCompress" $ do
  x <- B.p2AffCompress expectedAffPk2
  toHex x @?= expectedComp2

test_p2Uncompress :: TestTree
test_p2Uncompress = testCase "p2Uncompress" $ do
  x <- B.p2Uncompress $ fromHex expectedComp2
  x @?= Right expectedAffPk2

test_lendianFromScalar :: TestTree
test_lendianFromScalar = testCase "lendianFromScalar" $ do
  x <- B.lendianFromScalar expectedKey
  toHex x @?= expectedSerKey

test_scalarFromLendian :: TestTree
test_scalarFromLendian = testCase "scalarFromLendian" $ do
  x <- B.scalarFromLendian $ fromHex expectedSerKey
  x @?= expectedKey
