-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

module Test.BLST
  ( test_highlevel
  ) where

import Data.ByteArray (Bytes, convert)
import Data.ByteArray.Sized qualified as AS
import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty(..))
import Data.Proxy (Proxy(..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, testCase, (@?=))

import Crypto.BLST

import Test.BLST.Fixtures
import Test.BLST.Util

test_highlevel :: TestTree
test_highlevel = testGroup "High-level interface"
  [ withAllOptions "sign and verify" $ \(_ :: Proxy '(c, m)) ->
      verify @c @m sig pk msg noDST @?= BlstSuccess
  , withAllOptions "sign and verify with DST" $ \(_ :: Proxy '(c, m)) ->
      verify @c @m sigDST pk msg myDST @?= BlstSuccess
  , testGroup "PK"
    [ testGroup "Serialize"
        [ testCase "G1" $ serializePk @'G1 pk @?= expectedSer1
        , testCase "G2" $ serializePk @'G2 pk @?= expectedSer2
        ]
    , testGroup "Deserialize"
        [ testCase "G1" $ deserializePk @'G1 expectedSer1 @?= Right pk
        , testCase "G2" $ deserializePk @'G2 expectedSer2 @?= Right pk
        ]
    , testGroup "Compress"
        [ testCase "G1" $ compressPk @'G1 pk @?= fromHex expectedComp1
        , testCase "G2" $ compressPk @'G2 pk @?= fromHex expectedComp2
        ]
    , testGroup "Decompress"
        [ testCase "G1" $ decompressPk @'G1 (fromHex expectedComp1) @?= Right pk
        , testCase "G2" $ decompressPk @'G2 (fromHex expectedComp2) @?= Right pk
        ]
    ]
  , testGroup "SK"
      [ testCase "Serialize" $
          serializeSk key @?= AS.convert (fromHex expectedSerKey)
      , testCase "Deserialize" $
          deserializeSk (fromHex expectedSerKey) @?= key
      ]
  , withAllOptions "Serialize-deserialize signature roundtrip" $ \(_ :: Proxy '(c, m)) ->
      sigRoundtrip @c @m sig @?= Right sig
  , withAllOptions "Compress-decompress signature roundtrip" $ \(_ :: Proxy '(c, m)) ->
      sigCompRoundtrip @c @m sig @?= Right sig
  , withAllOptions "DST affects signature" $ \(_ :: Proxy '(c, m)) ->
      assertBool "signatures match when DSTs differ" $
        sig @m @c /= sigDST
  , withAllOptions "Aggregate" $ testAgg noDST
  , withAllOptions "Aggregate with DST" $ testAgg myDST
  ]

testAgg :: forall c m. (ToCurve m c) => Maybe Bytes -> Proxy '(c, m) -> IO ()
testAgg dst _ = do
  let sk1 = keygen $
        AS.unsafeSizedByteArray @32 @ByteString "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
      sk2 = keygen $
        AS.unsafeSizedByteArray @32 @ByteString "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
      (pk1, pk2) = (skToPk @c sk1, skToPk @c sk2)
      msg1 = "hello" :: ByteString
      msg2 = "world" :: ByteString
      sig1 = sign @c @m sk1 msg1 dst
      sig2 = sign @c @m sk2 msg2 dst
      sig3 = sign @c @m sk2 msg2 (Just ("xxx" :: ByteString))
      agg = aggregateSignatures (sig1 :| [sig2])
      agg' = aggregateSignatures (sig1 :| [sig2, sig3])
  aggregateVerify ((pk1, msg1) :| [(pk2, msg2)]) agg dst @?= Right True
  aggregateVerify ((pk1, msg1 <> "asd") :| [(pk2, msg2)]) agg dst @?= Right False
  aggregateVerify ((pk2, msg1) :| [(pk1, msg2)]) agg dst @?= Right False
  aggregateVerify ((pk1, msg1) :| [(pk2, msg2), (pk2, msg2)]) agg' dst @?= Right False

withAllOptions
  :: String
  -> (forall (c :: Curve) (m :: EncodeMethod). (ToCurve m c)
      => Proxy '(c, m) -> IO ())
  -> TestTree
withAllOptions name f = testGroup name
  [ testCase "G1 Hash"   $ f @'G1 @'Hash Proxy
  , testCase "G2 Hash"   $ f @'G2 @'Hash Proxy
  , testCase "G1 Encode" $ f @'G1 @'Encode Proxy
  , testCase "G2 Encode" $ f @'G2 @'Encode Proxy
  ]

sigRoundtrip
  :: IsCurve c
  => Signature c m
  -> Either BlstError (Signature c m)
sigRoundtrip = deserializeSignature . serializeSignature

sigCompRoundtrip
  :: IsCurve c
  => Signature c m
  -> Either BlstError (Signature c m)
sigCompRoundtrip = decompressSignature . compressSignature

key :: SecretKey
key = keygen $ AS.unsafeSizedByteArray @32 seed

pk :: IsCurve c => PublicKey c
pk = skToPk key

myDST :: Maybe Bytes
myDST = Just $ convert ("MY-DST" :: ByteString)

sig :: (ToCurve m c) => Signature c m
sig = sign key msg noDST

sigDST :: (ToCurve m c) => Signature c m
sigDST = sign key msg myDST
