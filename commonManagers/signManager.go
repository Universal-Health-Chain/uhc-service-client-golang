/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"crypto/ed25519"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
	"time"
)

func CreateEd25519SignKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	_, err := uuid.Parse(walletId)
	if err != nil {return nil, errors.New("WalletId is mandatory")}

	_, err = uuid.Parse(uhcOwnerId)
	if err != nil {return nil, errors.New("Owner ID is mandatory")}

	if len(purposes) == 0 { purposes = []string{""}}	// provisional while Purposes isn't an array to avoid nil errors

	// It generates public and private signing keys for Ed25519Signature2018
	publicSingKeyBytes, secretSignKeyBytes, err := ed25519.GenerateKey(nil)
	if err != nil {return nil, err}

	// ownerDid and purposes should be optional
	uuidRandomv4, _ := uuid.NewRandom()
	uuidv4String := uuidRandomv4.String()
	timestamp := time.Now()

	signKeyPair := &models.Key{
		ID:        		uuidv4String,
		WalletKeyId:	walletId,
		Tag:			tag,
		Type:           Ed25519KeyType,		// "Ed25519VerificationKey2018"
		CreatedAt:      &timestamp,
		// Expires:        &time.Time{},
		ControllerDID:    DIDMethod + uhcOwnerId, // not uhcOwnerId,
		PublicKeyDID:     DIDMethod + uhcOwnerId + "#" + uuidv4String,
		PublicKeyBase64:  BytesToBase64String(publicSingKeyBytes),
		PrivateKeyBase64: BytesToBase64String(secretSignKeyBytes),
		Purposes:         purposes,
	}

	return signKeyPair, nil
}

