-- SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
-- SPDX-License-Identifier: MPL-2.0

{-# OPTIONS_GHC -Wwarn #-}

module Test.BLST.Fixtures
  ( seed
  , msg
  , expectedKey
  , expectedPk1
  , expectedPk2
  , expectedHash1
  , expectedHash2
  , expectedSignHash1
  , expectedSignHash2
  , expectedEnc1
  , expectedEnc2
  , expectedSignEnc1
  , expectedSignEnc2
  , expectedAffPk1
  , expectedAffPk2
  , expectedSer1
  , expectedSer2
  , expectedComp1
  , expectedComp2
  , expectedSerKey
  , expectedAffSignHash1
  , expectedAffSignHash2
  , expectedAffSignEnc1
  , expectedAffSignEnc2
  ) where

import Data.ByteArray (Bytes)
import Data.ByteArray.Sized (SizedByteArray)
import Data.ByteArray.Sized qualified as AS
import Data.ByteString (ByteString)
import Data.Text (Text)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.BLST.Internal.Bindings qualified as B

import Test.BLST.Util

{-# ANN module ("HLint: ignore Missing NOINLINE pragma" :: Text) #-}

seed :: ByteString
seed = "asdfasdfasdfasdfasdfasdfasdfasdf"

msg :: ByteString
msg = "hello, world!"

expectedKey :: B.Scalar
expectedKey = unsafePerformIO $ B.scalarFromLendian $ fromHex expectedSerKey
{-# NOINLINE expectedKey #-}

expectedSerKey :: Text
expectedSerKey =
  "5ddb064f9378a723a172f364eaf8c069\
  \ef2ca9870c0928228c94c7a3adbdc20b"

expectedPk1 :: B.Point 'B.P1
expectedPk1 = deserializePoint
  "09afdbc09a9349f49da53fcf7ffc\
  \554394937510e14cbd6d330a02e8\
  \8d53b796c150abce2b953c3a7738\
  \86dae77dd867111a79f98c5102f2\
  \7993cc74875541c65bd9a220bc92\
  \b58bafb531e01deca18fcb5c8246\
  \1d8be54b6219d13e0aa96936"

expectedPk2 :: B.Point 'B.P2
expectedPk2 = deserializePoint' expectedSer2

-- NB: can't use serialized hash/enc because those roundtrip through affine
-- points loses information here.
expectedHash1 :: B.Point 'B.P1
expectedHash1 = B.Point $ AS.unsafeSizedByteArray $ fromHex'
  "3a69a985bb3c2c88c7c92141aaaba405\
  \ed352c7284c0108405b7977275595aba\
  \0d75772f5f4569a3a7aee43c1860770b\
  \8c2db24da8fe135325c0a3b77aec6e33\
  \dff54757f350c04af9057e4cb19424bf\
  \c1e6294cfa943925f6fe9607406ba705\
  \c5cdd8b0c4c9014695f13b4e2c6cc4ca\
  \e77b0f070a11a10840e373e97b17c79e\
  \68e0a9696907b5da815e6fc636065506"

expectedHash2 :: B.Point 'B.P2
expectedHash2 = B.Point $ AS.unsafeSizedByteArray $ fromHex'
  "818099f86b3d73fd53cd0768f379bb65\
  \0a4b4f2cee4dee97edd6b36834912877\
  \5bb1860418e0e8b10a82cb057142510f\
  \4240932247234c8e8c528ff1d2288471\
  \662f3b064b3cdb5b726bdc5c2fe3c10e\
  \b8d003ea272d2716c0f199b13fc4bb09\
  \29e7bbe9eec2ea0a7a3a678397c8e9af\
  \e9062296796065a9b673923e2a6b68fa\
  \97f1b29eaf17f3eb5728bb5fd24b6710\
  \66d10e7ff58b9355261d3bdf9c96ff63\
  \bc3c3d39b598e18ffe8d56cdf29cb61b\
  \f17f727f83f99a334f92bd2f03327114\
  \ef05a9368db5636a893a5878bfc30b08\
  \458b38c2cb6f2cda48c3ccb604c9740a\
  \4f9c644b437258bff2a45b323f4ba60d\
  \31e43c915daf976c5b24704b3f8d6dfc\
  \e336511e9a97ae32350ae5b9a32b2d1d\
  \8a594b22b1a31fd7795e510ef3fac908"

expectedEnc1 :: B.Point 'B.P1
expectedEnc1 = B.Point $ AS.unsafeSizedByteArray $ fromHex'
  "43bf72ddc6fb0b7b5cbafce921b11397\
  \3f3200ca0f81da5f8e2a7a3c8ac5b6d4\
  \f3b1a3ec20783c983b661b477e971512\
  \ed68359bef5ecc65a04c40ddb79da238\
  \d46753b3ceadab35f94c8cf38fe25f80\
  \e47fccbbe98ca3ccb6602df94c59d215\
  \c8b945158e6d7794fb628e7d8e307392\
  \bcc9f4f389c6011fb45b5ae4db11d4d5\
  \1b433e459a221ca6c4ff9a656a264a0b"

expectedEnc2 :: B.Point 'B.P2
expectedEnc2 = B.Point $ AS.unsafeSizedByteArray $ fromHex'
  "910646bb133d99d045bf023093b8b252\
  \1c5fa92d370cdeb4cbd7b5c0be024ae6\
  \263281bf060785e31ea85f6b86171818\
  \5728cd66f20930208d31008fbb45cbfb\
  \a74868b1703049031d8dcd474bc3a5de\
  \cf5825476d0fdd6c07b6ab530ce42903\
  \c147192266424eb261e78a4c16a15cfa\
  \0b17e0f13bf64b1a85fe804029a00ec2\
  \bbd34b335de66c5baa5cb077100fff04\
  \35ddc76afbae5cdc69421e5f98f1a6d8\
  \aa3a0e06ae3a8ae16dd3bee861605405\
  \244ac9c7da268c8d63cb1c0228390f15\
  \2f48f1cd1094323a44b6a246d30800a7\
  \cc5f480804b0e1ebf5169c6128e5d8b5\
  \4f429f7c4a354183cece49445564fc15\
  \b5c80f0a30fe9f5e8dacc392cca605c8\
  \63eaa48f433a68395e65e90c1da88d7f\
  \8f41f3c5e72795b65447f9735f6f0113"

expectedSignHash1 :: B.Point 'B.P2
expectedSignHash1 = deserializePoint
  "14369210233222d76103a4aa744a300f\
  \87dea5f5b8f1538415d85f477e4b004c\
  \c82569e620af5ce7d1532e465b9b1396\
  \06601565e7564a7c7013b71ce2cbdabc\
  \ea9db6c3244c6b33e6256f6c46f7257d\
  \561c88325a3c9cf725131f30d1c31b22\
  \124575a776f9704c20f2f35d695e51ec\
  \62afac092148a62bb5e0f058c0420b26\
  \1287c7edf2d3de8c492ce74c2e31bad7\
  \059dd86ac9796a69ddd1c9617cf61ba3\
  \b30e8bac3471bf3ae83b8085081f0ad5\
  \11157a6e89dcb890de3ce8a8c1348e09"

expectedAffSignHash1 :: B.Affine 'B.P2
expectedAffSignHash1 = unsafePerformIO $ B.p2ToAffine expectedSignHash1
{-# NOINLINE expectedAffSignHash1 #-}

expectedSignHash2 :: B.Point 'B.P1
expectedSignHash2 = deserializePoint
  "12c440df3381393ae09dd06a45c1b721\
  \816109f066b9669607b3f1c4febfd477\
  \01ea040e19e97ca9a70361ce25be3347\
  \126e269e38e6b485082c909b84ff191e\
  \861a2061441534429789e04b58303407\
  \5c68bc178f8ea96b2556ca1fb9611f93"

expectedAffSignHash2 :: B.Affine 'B.P1
expectedAffSignHash2 = unsafePerformIO $ B.p1ToAffine expectedSignHash2
{-# NOINLINE expectedAffSignHash2 #-}

expectedSignEnc1 :: B.Point 'B.P2
expectedSignEnc1 = deserializePoint
  "14093f93072f22ddf7957964786bf6ef\
  \0f27c8b0733f374f8ca29f7ca08eeb9e\
  \1aa893264553d970a7487688aad4aa67\
  \0d5e0d87267a63c9ce44340f625df5d6\
  \54d9a10eba66fd8e5d925fcc4bd37d81\
  \63b9e55142932bab720d23af46270c5f\
  \05880b4da102e19f7a4f8daf2e28d158\
  \ce36fb065bcf8bf5d76aef43a0a2163a\
  \e737192dbdced1e9afdadc5c933be231\
  \0507cf96ae04aa838384d612a9edbeb9\
  \ea336b737f20efdf4c7754ab9482064d\
  \b49d3e01d4953948cb4d8978defd0bcf"

expectedAffSignEnc1 :: B.Affine 'B.P2
expectedAffSignEnc1 = unsafePerformIO $ B.p2ToAffine expectedSignEnc1
{-# NOINLINE expectedAffSignEnc1 #-}

expectedSignEnc2 :: B.Point 'B.P1
expectedSignEnc2 = deserializePoint
  "0ac71a17ad14546bbaa8f6689e5f4960\
  \7c377fa978cf92a37699dbdd680dcf77\
  \f85d8ba7f65639f74e1b2bba6d4af073\
  \115327fd424560691b171978fd436c55\
  \9597cced904e5b65e5e1a5e4b5497b90\
  \08dacc92a1e6d22ade43fdbddd487519"

expectedAffSignEnc2 :: B.Affine 'B.P1
expectedAffSignEnc2 = unsafePerformIO $ B.p1ToAffine expectedSignEnc2
{-# NOINLINE expectedAffSignEnc2 #-}

expectedAffPk1 :: B.Affine 'B.P1
expectedAffPk1 = deserializeAffine' expectedSer1

expectedAffPk2 :: B.Affine 'B.P2
expectedAffPk2 = deserializeAffine' expectedSer2

expectedSer1 :: SizedByteArray B.P1SerializeSize Bytes
expectedSer1 = fromHex
  "09afdbc09a9349f49da53fcf7ffc5543\
  \94937510e14cbd6d330a02e88d53b796\
  \c150abce2b953c3a773886dae77dd867\
  \111a79f98c5102f27993cc74875541c6\
  \5bd9a220bc92b58bafb531e01deca18f\
  \cb5c82461d8be54b6219d13e0aa96936"

expectedSer2 :: SizedByteArray B.P2SerializeSize Bytes
expectedSer2 = fromHex
  "0fe7542b55fdf24f0a4fe2027f8f9c60\
  \74264eae84f83db8971d7ef8eb896406\
  \250e38be84b4443ab96a47c799261077\
  \080a849ce688e74b5c4cbd50b4f1cd66\
  \f4e41026813c7744f0e44a31876c2eca\
  \ef4550c78f829ededb3b14d870ac12e5\
  \0e8ab71a728201234283b5f1a01ebdfd\
  \54e2ceb7f3663a11c45f56badf624ad5\
  \01692a2bae776563eaa090aa45e00dfc\
  \0514c252a98b86e2f5054d597be4ef8c\
  \3697342dc336a5ffaba36da3e141972f\
  \8463cc9126d55bb7f18048569c9e6366"

expectedComp1 :: Text
expectedComp1 =
  "a9afdbc09a9349f49da53fcf7ffc5543\
  \94937510e14cbd6d330a02e88d53b796\
  \c150abce2b953c3a773886dae77dd867"

expectedComp2 :: Text
expectedComp2 =
  "afe7542b55fdf24f0a4fe2027f8f9c60\
  \74264eae84f83db8971d7ef8eb896406\
  \250e38be84b4443ab96a47c799261077\
  \080a849ce688e74b5c4cbd50b4f1cd66\
  \f4e41026813c7744f0e44a31876c2eca\
  \ef4550c78f829ededb3b14d870ac12e5"
