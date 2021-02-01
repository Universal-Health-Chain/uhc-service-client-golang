/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	// "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	// "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	// "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"

	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"

)

type KeyPairManager struct {
}

func (manager *KeyPairManager) CreateEd25519SignKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	return CreateEd25519SignKeyPair(walletId, uhcOwnerId, purposes, tag)
}

func (manager *KeyPairManager) CreateX25519EncryptKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	return CreateX25519EncryptKeyPair(walletId, uhcOwnerId, purposes, tag)
}

func (manager *KeyPairManager) CreateAuthcryptKeysetHandle() (*keyset.Handle, error) {
	// authcryptTemplate := ecdh.ECDH256KWAES256GCMKeyTemplate()
	authcryptTemplate := X25519XChachaECDHKeyTemplate()
	// keyset.MemReaderWriter {Keyset: nil, EncryptedKeyset: nil}
	return  keyset.NewHandle(authcryptTemplate)
}

// X25519XChachaECDHKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for XChacha20Poly1305 content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service). It is used to represent a key
// to execute the CompositeDecrypt primitive with the following parameters:
//  - Content Encryption: XChaha20Poly1305
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519

func X25519XChachaECDHKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(false, false, commonpb.EllipticCurveType_CURVE25519, nil)
}

func (manager *KeyPairManager) GetPublicCompositeKeyByKeyset(keysetHandle *keyset.Handle) (*cryptoapi.PublicKey, error) {
	publicKeyBytesByKeyset, err := manager.GetPublicKeyBytesByKeyset(keysetHandle)
	if err != nil {
		return nil, err
	}

	compositePubKey := new(cryptoapi.PublicKey)
	err = json.Unmarshal(publicKeyBytesByKeyset, compositePubKey)
	if err != nil {
		return nil, err
	}

	return compositePubKey, err
}

func (manager *KeyPairManager) GetPublicKeyBytesByKeyset(keyHandle *keyset.Handle) ([]byte, error) {
	publicKeysetHandle, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	publicKeyBuffer := new(bytes.Buffer)
	publicKeyioWriter := keyio.NewWriter(publicKeyBuffer)

	err = publicKeysetHandle.WriteWithNoSecrets(publicKeyioWriter)
	if err != nil {
		return nil, err
	}

	return publicKeyBuffer.Bytes(), nil
}

// Methods to be used when receiving the public key of the sender to unpack JWE messages

// TODO: test if it works with public or private Ed25519 key bytes
func (manager *KeyPairManager) GetPublicCompositeKeyByXXBytes(keyBytes []byte) (*cryptoapi.PublicKey, error) {
	var publicCompositeKey *cryptoapi.PublicKey
	err := json.Unmarshal(keyBytes, &publicCompositeKey)
	if err != nil {
		return nil, errors.New("Failed converting key bytes: " + err.Error())
	}

	return publicCompositeKey, nil
}

func (manager *KeyPairManager) GetPublicCompositeKeyByBase58(publicKeyBase58 *string) (*cryptoapi.PublicKey, error) {
	publicKeyBytes,err := manager.GetPublicKeyBytesByBase58(publicKeyBase58)
	if err != nil { return nil, err }

	return manager.GetPublicCompositeKeyByXXBytes(publicKeyBytes)
}

func (manager *KeyPairManager) GetPublicKeyBytesByBase58(publicKeyBase58 *string) ([]byte, error) {
	if publicKeyBase58 == nil {
		return nil, errors.New("No sender public key received")
	}

	publicSenderKeyBytes := base58.Decode(*publicKeyBase58)
	return publicSenderKeyBytes, nil
}

// createKeyTemplate creates a new ECDH-AEAD key template with the set cek for primitive execution. Boolean flags used:
//  - nistpKW flag to state if kw is either NIST P curves (true) or Curve25519 (false)
//  - aesEnc flag to state if content encryption is either AES256-GCM (true) or XChacha20Poly1305 (false)
func createKeyTemplate(nistpKW, aesEnc bool, c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	var encTemplate *tinkpb.KeyTemplate

	typeURL, keyType := getTypeParams(nistpKW, aesEnc)

	if aesEnc {
		encTemplate = aead.AES256GCMKeyTemplate()
	} else {
		encTemplate = aead.XChaCha20Poly1305KeyTemplate()
	}

	format := &ecdhpb.EcdhAeadKeyFormat{
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   keyType,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encTemplate,
				CEK:     cek,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal EcdhAeadKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

const (
	ecdhNISTPAESPrivateKeyVersion = 0
	ecdhNISTPAESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwAesAeadPrivateKey"
	ecdhNISTPXChachaPrivateKeyVersion = 0
	ecdhNISTPXChachaPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhNistPKwXChachaAeadPrivateKey" // nolint:lll
	ecdhX25519AESPrivateKeyVersion = 0
	ecdhX25519AESPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwAesAeadPrivateKey"
	ecdhX25519XChachaPrivateKeyVersion = 0
	ecdhX25519XChachaPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhX25519KwXChachaAeadPrivateKey" // nolint:lll

	)

func getTypeParams(nispKW, aesEnc bool) (string, ecdhpb.KeyType) {
	if nispKW {
		if aesEnc {
			return ecdhNISTPAESPrivateKeyTypeURL, ecdhpb.KeyType_EC
		}

		return ecdhNISTPXChachaPrivateKeyTypeURL, ecdhpb.KeyType_EC
	}

	if aesEnc {
		return ecdhX25519AESPrivateKeyTypeURL, ecdhpb.KeyType_OKP
	}

	return ecdhX25519XChachaPrivateKeyTypeURL, ecdhpb.KeyType_OKP
}
