/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"bytes"
	"encoding/json"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
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
	return  keyset.NewHandle(authcryptTemplate)
}

func (manager *KeyPairManager) GetCompositePublicKey(keysetHandle *keyset.Handle) (*composite.PublicKey, error) {
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

// func (manager *KeyPairManager) GetByKeysetHandle(keyUHC *models.Key, masterKey tink.AEAD) (*keyset.Handle, error) {keysetHandle, err := keyset.Read(bytes.Reader{}, masterKey)}