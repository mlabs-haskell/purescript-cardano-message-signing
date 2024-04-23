-- | Implements CIP-8 message signing
module Cardano.MessageSigning
  ( DataSignature
  , signData
  ) where

import Prelude

import Cardano.AsCbor (encodeCbor)
import Cardano.Types.Address (Address)
import Cardano.Types.CborBytes (CborBytes(CborBytes))
import Cardano.Types.PrivateKey (PrivateKey)
import Cardano.Types.PrivateKey as PrivateKey
import Cardano.Types.PublicKey as PublicKey
import Cardano.Types.RawBytes (RawBytes(RawBytes))
import Data.ByteArray (ByteArray)
import Data.Newtype (unwrap)
import Effect (Effect)

type DataSignature =
  { key :: CborBytes
  , signature :: CborBytes
  }

foreign import data COSESign1Builder :: Type
foreign import newCoseSign1Builder
  :: ByteArray -> Headers -> Effect COSESign1Builder

foreign import makeDataToSign :: COSESign1Builder -> ByteArray
foreign import buildSignature :: COSESign1Builder -> ByteArray -> ByteArray

foreign import data Headers :: Type
foreign import newHeaders :: HeaderMap -> ProtectedHeaderMap -> Headers

foreign import data ProtectedHeaderMap :: Type
foreign import newProtectedHeaderMap :: HeaderMap -> ProtectedHeaderMap

foreign import data HeaderMap :: Type
foreign import newHeaderMap :: Effect HeaderMap
foreign import setAlgHeaderToEdDsa :: HeaderMap -> Effect Unit
foreign import setAddressHeader :: CborBytes -> HeaderMap -> Effect Unit

foreign import data COSEKey :: Type
foreign import newCoseKeyWithOkpType :: Effect COSEKey
foreign import setCoseKeyAlgHeaderToEdDsa :: COSEKey -> Effect Unit
foreign import setCoseKeyCrvHeaderToEd25519 :: COSEKey -> Effect Unit
foreign import setCoseKeyXHeader :: RawBytes -> COSEKey -> Effect Unit
foreign import bytesFromCoseKey :: COSEKey -> CborBytes

-- | Sign a given byte string using a private key.
-- |
-- | Implements message signing compatible with CIP-30 (CIP-8) `signData` method.
-- |
-- | Use `Cardano.Types.PublicKey.verify` for signature verification.
signData :: PrivateKey -> Address -> RawBytes -> Effect DataSignature
signData privatePaymentKey address (RawBytes payload) =
  { key: _, signature: _ } <$> key <*> signature
  where
  key :: Effect CborBytes
  key = do
    coseKey <- newCoseKeyWithOkpType
    setCoseKeyAlgHeaderToEdDsa coseKey
    setCoseKeyCrvHeaderToEd25519 coseKey
    setCoseKeyXHeader publicPaymentKeyBytes coseKey
    pure $ bytesFromCoseKey coseKey
    where
    publicPaymentKeyBytes :: RawBytes
    publicPaymentKeyBytes =
      PublicKey.toRawBytes (PrivateKey.toPublicKey privatePaymentKey)

  signature :: Effect CborBytes
  signature = CborBytes <$> (buildSignature <$> builder <*> signedSigStruct)
    where
    signedSigStruct :: Effect ByteArray
    signedSigStruct =
      unwrap <<< encodeCbor
        <<< PrivateKey.sign privatePaymentKey
        <<< makeDataToSign <$> builder

    builder :: Effect COSESign1Builder
    builder = headers >>= newCoseSign1Builder payload
      where
      headers :: Effect Headers
      headers = newHeaders <$> newHeaderMap <*> protectedHeaders

      protectedHeaders :: Effect ProtectedHeaderMap
      protectedHeaders = do
        headerMap <- newHeaderMap
        setAlgHeaderToEdDsa headerMap
        setAddressHeader (encodeCbor address) headerMap
        pure $ newProtectedHeaderMap headerMap
