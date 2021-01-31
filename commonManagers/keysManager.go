/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/mr-tron/base58"
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
	authcryptTemplate := ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate()
	// keyset.MemReaderWriter {Keyset: nil, EncryptedKeyset: nil}
	return  keyset.NewHandle(authcryptTemplate)
}

func (manager *KeyPairManager) GetCompositePublicKeyByKeyset(keysetHandle *keyset.Handle) (*composite.PublicKey, error) {
	publicKeysetHandle, err := keysetHandle.Public() // Public returns a Handle of the public keys if the managed keyset contains private keys.
	// require.NoError(t, err)

	publicKeyBuffer := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(publicKeyBuffer)
	err = publicKeysetHandle.WriteWithNoSecrets(pubKeyWriter) // writes public info in publicKeyBuffer
	// require.NoError(t, err)
	// return publicKeyBuffer.Bytes(), keysetHandle, err

	// for each entity, for i := 0; i < numberOfEntities; i++ {
	// mrKey, kh := createAndMarshalEntityKey(t, isECDHES)
	compositePubKey := new(composite.PublicKey)
	err = json.Unmarshal(publicKeyBuffer.Bytes(), compositePubKey)

	// require.NoError(t, err)
	return compositePubKey, err
}

func (manager *KeyPairManager) ExportKeysetHandlePubKeyBytes(keyHandle *keyset.Handle) ([]byte, error) {
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
func (manager *KeyPairManager) FetchSenderPublicKeyBytesByBase58(senderPublicKeyBase58 *string) ([]byte, error) {
	if senderPublicKeyBase58 == nil {
		return nil, errors.New("No sender public key received")
	}

	publicSenderKeyBytes, err := base58.Decode(*senderPublicKeyBase58)
	if err != nil {
		return nil, errors.New("Invalid public key Base58 format")
	}
	return publicSenderKeyBytes, nil
}

func (manager *KeyPairManager) FetchSenderCompositePublicKeyByBase58(senderPublicKeyBase58 *string) (*composite.PublicKey, error) {
	publicSenderKeyBytes,err := manager.FetchSenderPublicKeyBytesByBase58(senderPublicKeyBase58)
	if err != nil { return nil, err }

	var publicSenderCompositeKey *composite.PublicKey
	err = json.Unmarshal(publicSenderKeyBytes, &publicSenderCompositeKey)
	if err != nil {
		return nil, errors.New("Failed converting sender key bytes")
	}

	return publicSenderCompositeKey, nil

}