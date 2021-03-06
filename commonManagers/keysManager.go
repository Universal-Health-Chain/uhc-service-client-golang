/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type KeyPairManager struct {
}

func (manager *KeyPairManager) CreateEd25519SignKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	return CreateEd25519SignKeyPair(walletId, uhcOwnerId, purposes, tag)
}

func (manager *KeyPairManager) CreateX25519EncryptKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	return CreateX25519EncryptKeyPair(walletId, uhcOwnerId, purposes, tag)
}
