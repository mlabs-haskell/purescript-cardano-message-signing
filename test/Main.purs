module Test.Main where

import Prelude

import Cardano.AsCbor (encodeCbor)
import Cardano.MessageSigning (DataSignature, signData)
import Cardano.Types.Address (Address(BaseAddress, EnterpriseAddress))
import Cardano.Types.CborBytes (CborBytes)
import Cardano.Types.Credential (Credential(PubKeyHashCredential))
import Cardano.Types.NetworkId (NetworkId(MainnetId))
import Cardano.Types.NetworkId as NetworkId
import Cardano.Types.PaymentCredential (PaymentCredential(PaymentCredential))
import Cardano.Types.PrivateKey (PrivateKey)
import Cardano.Types.PrivateKey as PrivateKey
import Cardano.Types.PublicKey (PublicKey)
import Cardano.Types.PublicKey as PublicKey
import Cardano.Types.RawBytes (RawBytes)
import Cardano.Types.StakeCredential (StakeCredential(StakeCredential))
import Data.ByteArray (byteArrayFromIntArrayUnsafe)
import Data.Foldable (traverse_)
import Data.Maybe (Maybe(Just, Nothing), fromJust, fromMaybe, maybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Effect (Effect)
import Effect.Aff (Aff, error, launchAff_)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Exception (throw, throwException)
import Partial.Unsafe (unsafePartial)
import Test.QuickCheck.Arbitrary (class Arbitrary, arbitrary)
import Test.QuickCheck.Gen (Gen, chooseInt, randomSample, vectorOf)
import Test.Spec (describe, it)
import Test.Spec.Reporter.Console (consoleReporter)
import Test.Spec.Runner (runSpec)

main :: Effect Unit
main = launchAff_ $ runSpec [ consoleReporter ] $ do
  describe "signData (CIP-30)" do
    it "generates a valid signature and key for a given payload" do
      traverse_ testCip30SignData =<< liftEffect (randomSample arbitrary)

testCip30SignData :: TestInput -> Aff Unit
testCip30SignData { privateKey, privateStakeKey, payload, networkId } = do
  let
    address = privateKeysToAddress (wrap $ unwrap privateKey)
      ((wrap <<< unwrap) <$> privateStakeKey)
      (unwrap networkId)

  dataSignature <- liftEffect $ signData (privatePaymentKey) address
    payload
  { coseKey } <- checkCip30SignDataResponse address dataSignature

  assertTrue "COSE_Key's x (-2) header must be set to public key bytes"
    (getCoseKeyHeaderX coseKey == Just (PublicKey.toRawBytes publicPaymentKey))
  where
  privatePaymentKey :: PrivateKey
  privatePaymentKey = unwrap privateKey

  publicPaymentKey :: PublicKey
  publicPaymentKey = PrivateKey.toPublicKey privatePaymentKey

checkCip30SignDataResponse
  :: Address -> DataSignature -> Aff DeserializedDataSignature
checkCip30SignDataResponse address { key, signature } = do
  coseSign1 <- liftEffect $ fromBytesCoseSign1 signature
  coseKey <- liftEffect $ fromBytesCoseKey key

  checkCoseSign1ProtectedHeaders coseSign1
  checkCoseKeyHeaders coseKey
  checkKidHeaders coseSign1 coseKey
  liftEffect $ checkVerification coseSign1 coseKey
  pure { coseKey, coseSign1 }
  where
  checkCoseSign1ProtectedHeaders :: COSESign1 -> Aff Unit
  checkCoseSign1ProtectedHeaders coseSign1 = do
    assertTrue "COSE_Sign1's alg (1) header must be set to EdDSA (-8)"
      (getCoseSign1ProtectedHeaderAlg coseSign1 == Just (-8))

    assertTrue "COSE_Sign1's \"address\" header must be set to address bytes"
      ( getCoseSign1ProtectedHeaderAddress coseSign1
          == Just (encodeCbor address)
      )

  checkCoseKeyHeaders :: COSEKey -> Aff Unit
  checkCoseKeyHeaders coseKey = do
    assertTrue "COSE_Key's kty (1) header must be set to OKP (1)"
      (getCoseKeyHeaderKty coseKey == Just 1)

    assertTrue "COSE_Key's alg (3) header must be set to EdDSA (-8)"
      (getCoseKeyHeaderAlg coseKey == Just (-8))

    assertTrue "COSE_Key's crv (-1) header must be set to Ed25519 (6)"
      (getCoseKeyHeaderCrv coseKey == Just (6))

  checkKidHeaders :: COSESign1 -> COSEKey -> Aff Unit
  checkKidHeaders coseSign1 coseKey =
    assertTrue
      "COSE_Sign1's kid (4) and COSE_Key's kid (2) headers, if present, must \
      \be set to the same value"
      (getCoseSign1ProtectedHeaderKid coseSign1 == getCoseKeyHeaderKid coseKey)

  checkVerification :: COSESign1 -> COSEKey -> Effect Unit
  checkVerification coseSign1 coseKey = do
    publicKey <-
      errMaybe "COSE_Key's x (-2) header must be set to public key bytes"
        $ getCoseKeyHeaderX coseKey >>= PublicKey.fromRawBytes
    sigStructBytes <- getSignedData coseSign1
    assertTrue "Signature verification failed"
      =<< verifySignature coseSign1 publicKey sigStructBytes

--------------------------------------------------------------------------------
-- Arbitrary
--------------------------------------------------------------------------------

type TestInput =
  { privateKey :: ArbitraryPrivatePaymentKey
  , privateStakeKey :: Maybe ArbitraryPrivateStakeKey
  , payload :: RawBytes
  , networkId :: ArbitraryNetworkId
  }

type DeserializedDataSignature =
  { coseKey :: COSEKey
  , coseSign1 :: COSESign1
  }

newtype ArbitraryPrivatePaymentKey =
  ArbitraryPrivatePaymentKey PrivateKey

derive instance Newtype ArbitraryPrivatePaymentKey _

instance Arbitrary ArbitraryPrivatePaymentKey where
  arbitrary =
    wrap <<< unwrap <$> (arbitrary :: Gen ArbitraryPrivateKey)

newtype ArbitraryPrivateStakeKey = ArbitraryPrivateStakeKey PrivateKey

derive instance Newtype ArbitraryPrivateStakeKey _

instance Arbitrary ArbitraryPrivateStakeKey where
  arbitrary =
    wrap <<< unwrap <$> (arbitrary :: Gen ArbitraryPrivateKey)

newtype ArbitraryPrivateKey = ArbitraryPrivateKey PrivateKey

derive instance Newtype ArbitraryPrivateKey _

instance Arbitrary ArbitraryPrivateKey where
  arbitrary =
    wrap <<< unsafePartial fromJust <$>
      (PrivateKey.fromRawBytes <$> privateKeyBytes)
    where
    privateKeyBytes :: Gen RawBytes
    privateKeyBytes =
      wrap <<< byteArrayFromIntArrayUnsafe <$> vectorOf 32 (chooseInt 0 255)

newtype ArbitraryNetworkId = ArbitraryNetworkId NetworkId

derive instance Newtype ArbitraryNetworkId _

instance Arbitrary ArbitraryNetworkId where
  arbitrary =
    wrap <<< fromMaybe MainnetId <<< NetworkId.fromInt <$> chooseInt 0 1

newtype PrivatePaymentKey = PrivatePaymentKey PrivateKey

derive instance Newtype PrivatePaymentKey _
newtype PrivateStakeKey = PrivateStakeKey PrivateKey

derive instance Newtype PrivateStakeKey _

--------------------------------------------------------------------------------
-- Functions from other PureScript modules related to CTL. Copy-pasted to avoid
-- circular dependencies.
--------------------------------------------------------------------------------

privateKeysToAddress
  :: PrivatePaymentKey -> Maybe PrivateStakeKey -> NetworkId -> Address
privateKeysToAddress payKey mbStakeKey networkId = do
  let pubPayKey = PrivateKey.toPublicKey (unwrap payKey)
  case mbStakeKey of
    Just stakeKey ->
      let
        pubStakeKey = PrivateKey.toPublicKey (unwrap stakeKey)
      in
        BaseAddress
          { networkId
          , paymentCredential:
              ( PaymentCredential $ PubKeyHashCredential $ PublicKey.hash $
                  pubPayKey
              )
          , stakeCredential:
              ( StakeCredential $ PubKeyHashCredential $ PublicKey.hash $
                  pubStakeKey
              )
          }

    Nothing -> pubPayKey # PublicKey.hash
      >>> PubKeyHashCredential
      >>> wrap
      >>> { networkId, paymentCredential: _ }
      >>> EnterpriseAddress

getCoseSign1ProtectedHeaderAlg :: COSESign1 -> Maybe Int
getCoseSign1ProtectedHeaderAlg = _getCoseSign1ProtectedHeaderAlg maybeFfiHelper

getCoseSign1ProtectedHeaderAddress :: COSESign1 -> Maybe CborBytes
getCoseSign1ProtectedHeaderAddress =
  _getCoseSign1ProtectedHeaderAddress maybeFfiHelper

type MaybeFfiHelper =
  { nothing :: forall (x :: Type). Maybe x
  , just :: forall (x :: Type). x -> Maybe x
  , from :: forall (x :: Type). x -> Maybe x -> x
  }

maybeFfiHelper :: MaybeFfiHelper
maybeFfiHelper = { nothing: Nothing, just: Just, from: fromMaybe }

getCoseKeyHeaderKty :: COSEKey -> Maybe Int
getCoseKeyHeaderKty = _getCoseKeyHeaderKty maybeFfiHelper

getCoseKeyHeaderAlg :: COSEKey -> Maybe Int
getCoseKeyHeaderAlg = _getCoseKeyHeaderAlg maybeFfiHelper

getCoseKeyHeaderCrv :: COSEKey -> Maybe Int
getCoseKeyHeaderCrv = _getCoseKeyHeaderCrv maybeFfiHelper

getCoseSign1ProtectedHeaderKid :: COSESign1 -> Maybe RawBytes
getCoseSign1ProtectedHeaderKid = _getCoseSign1ProtectedHeaderKid maybeFfiHelper

getCoseKeyHeaderKid :: COSEKey -> Maybe RawBytes
getCoseKeyHeaderKid = _getCoseKeyHeaderKid maybeFfiHelper

assertTrue
  :: forall (m :: Type -> Type)
   . Applicative m
  => MonadEffect m
  => String
  -> Boolean
  -> m Unit
assertTrue msg b = unless b $ liftEffect $ throwException $ error msg

errMaybe
  :: forall (m :: Type -> Type) (a :: Type)
   . MonadEffect m
  => String
  -> Maybe a
  -> m a
errMaybe msg = maybe (liftEffect $ throw msg) pure

getCoseKeyHeaderX :: COSEKey -> Maybe RawBytes
getCoseKeyHeaderX = _getCoseKeyHeaderX maybeFfiHelper

--------------------------------------------------------------------------------
-- Foreign functions
--------------------------------------------------------------------------------

foreign import _getCoseSign1ProtectedHeaderAlg
  :: MaybeFfiHelper -> COSESign1 -> Maybe Int

foreign import _getCoseSign1ProtectedHeaderAddress
  :: MaybeFfiHelper -> COSESign1 -> Maybe CborBytes

foreign import data COSEKey :: Type
foreign import data COSESign1 :: Type
foreign import _getCoseKeyHeaderX :: MaybeFfiHelper -> COSEKey -> Maybe RawBytes
foreign import _getCoseKeyHeaderKty :: MaybeFfiHelper -> COSEKey -> Maybe Int
foreign import _getCoseKeyHeaderAlg :: MaybeFfiHelper -> COSEKey -> Maybe Int
foreign import _getCoseKeyHeaderCrv :: MaybeFfiHelper -> COSEKey -> Maybe Int
foreign import _getCoseSign1ProtectedHeaderKid
  :: MaybeFfiHelper -> COSESign1 -> Maybe RawBytes

foreign import _getCoseKeyHeaderKid
  :: MaybeFfiHelper -> COSEKey -> Maybe RawBytes

foreign import getSignedData :: COSESign1 -> Effect CborBytes

foreign import verifySignature
  :: COSESign1 -> PublicKey -> CborBytes -> Effect Boolean

foreign import fromBytesCoseSign1 :: CborBytes -> Effect COSESign1
foreign import fromBytesCoseKey :: CborBytes -> Effect COSEKey

