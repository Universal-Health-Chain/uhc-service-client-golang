package commonManagers

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/subtle"
	cryptoapi "github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	gojosev3 "github.com/square/go-jose/v3"
	ariesjose "github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/jose"
	/*
		"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
		hybrid "github.com/google/tink/go/hybrid/subtle"
		"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
		"github.com/google/tink/go/keyset"
		"crypto/ed25519"
		"crypto/elliptic"
		"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
		"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
		"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
		"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	*/
)

type EncAlg string	// it represents the JWE content encryption algorithm
const A256GCM = EncAlg(ariesjose.A256GCM)	// for AES256GCM content encryption

// -- from Aries 0.1.5
func convertToGoJoseRecipients(t *testing.T, keys []*cryptoapi.PublicKey, kids []string) []gojosev3.Recipient {
	t.Helper()
	var joseRecipients []gojosev3.Recipient
	for i, key := range keys {
		c := subtle.GetCurve(key.Curve)
		gjKey := gojosev3.Recipient{
			KeyID:     kids[i],
			Algorithm: gojosev3.ECDH_ES_A256KW,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(key.X),
				Y:     new(big.Int).SetBytes(key.Y),
			},
		}
		joseRecipients = append(joseRecipients, gjKey)
	}

	/*
		testkey := gojosev3.Recipient{
			Algorithm:  gojosev3.ED25519,
			Key:         &cryptoapi.PublicKey{
				KID:   "",
				X:     nil,
				Y:     nil,
				Curve: "",
				Type:  "",
			},
			KeyID:      "",
		}
	*/

	return joseRecipients
}

func TestECDH1PU(t *testing.T) {
	// recipients, recKHs, _ := createRecipients(t, 2)
	// senders, senderKHs, senderKIDs := createRecipients(t, 1)
	// tinkCrypto, k := createCryptoAndKMSServices(t, recKHs)

	tinkCrypto := tinkcrypto.Crypto{}
	var keyManager KeyPairManager

	// It creates a new sender Keyset Handle (private + public key info) by a tink template
	senderKeysetHandle, err := keyManager.CreateAuthcryptKeysetHandle()
	require.NoError(t, err)
	senderPublicKeyBytes, err := keyManager.GetPublicKeyBytesByKeyset(senderKeysetHandle)
	require.NoError(t, err)
	senderPublicKID := base58.Encode(senderPublicKeyBytes)

	// It creates a new recipient's Keyset Handle (private + public key info) and then gets *cryptoapi.PublicKey (*composite.PublicKey in Aries 0.1.4)
	recipientKeysetHandle, err := keyManager.CreateAuthcryptKeysetHandle()
	require.NoError(t, err)
	recipientCryptoPublicKey, err := keyManager.GetPublicCompositeKeyByKeyset(recipientKeysetHandle)
	require.NoError(t, err)
	// curveType, err := composite.GetCurveType(recipientCryptoPublicKey.Curve) // changed from Aries 0.1.5
	fmt.Printf("GetCurvetype = %v \n", recipientCryptoPublicKey.Curve) // NIST_P256
	// keyType, err := composite.GetKeyType(recipientCryptoPublicKey.Type)	// changed from Aries 0.1.5
	fmt.Printf("GetKeyType = %v \n", recipientCryptoPublicKey.Type) // EC

	// It gets the public Key ID (KID) of the recipient using the smae public key bytes in base58 as KID
	// recipientPublicKeyBytes, err := keyManager.GetPublicKeyBytesByKeyset(recipientKeysetHandle)
	require.NoError(t, err)
	// recipientPublicKID := base58.Encode(recipientPublicKeyBytes)

	// ------------ Not working
	// recipientPublicKeyBase58ForTesting := base58.Encode(Ed25519PublicKeyBytesForTesting)
	// recipientCryptoPublicKey, err = keyManager.GetPublicCompositeKeyByBytes(Ed25519PublicKeyBytesForTesting)
	// recipientCryptoPublicKey, err = keyManager.GetPublicCompositeKeyByXXBytes(Ed25519PublicKeyBytesForTesting)
	// ------------

	// It creates an array of publicKeys of recipients to encrypt for
	var recipientCompositePublicKeys []*cryptoapi.PublicKey
	recipientCompositePublicKeys = append(recipientCompositePublicKeys, recipientCryptoPublicKey)

	jweEnc, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, ariesjose.DIDCommEncType, senderPublicKID,
		senderKeysetHandle, []*cryptoapi.PublicKey{recipientCryptoPublicKey}, &tinkCrypto)
	require.NoError(t, err)
	require.NotEmpty(t, jweEnc)

	// mockStoreMap := make(map[string][]byte)
	// mockStore := &mockstorage.MockStore{ Store: mockStoreMap, }

	payloadBytes := []byte("plaintext payload")

	// test JWEEncrypt for ECDH1PU
	jwe, err := jweEnc.Encrypt(payloadBytes)
	require.NoError(t, err)

	// -- this is Aries 0.1.4 test example
	// It serializes the encrypted JWE message to be sent
	var serializedJWE string
	if len(recipientCompositePublicKeys) == 1 {
		serializedJWE, err = jwe.CompactSerialize(json.Marshal)
	} else {
		serializedJWE, err = jwe.FullSerialize(json.Marshal)
	}
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)
	fmt.Printf("Serialized JWE = %v \n", serializedJWE)

	// Now it deserializes the received message
	jweReceived, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)
	fmt.Printf("Deserialized JWE = %v \n", jweReceived)

	// -- this is Aries 0.1.5 test example
	serializedJWE, err = jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)
	fmt.Printf("serializedJWE = %v \n", serializedJWE)

	deserializedJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)
	fmt.Printf("deserializedJWE = %v \n", deserializedJWE)


	/* TODO: test Unpack ECDH-1PU



	/*
	t.Run("Decrypting JWE message without sender key in the third party store should fail", func(t *testing.T) {
		jd := ariesjose.NewJWEDecrypt(mockStore, &tinkCrypto, k)
		require.NotEmpty(t, jd)

		_, err = jd.Decrypt(localJWE)
		require.EqualError(t, err, "jwedecrypt: failed to add sender public key for skid: failed to get sender"+
			" key from DB: data not found")
	})

	// add sender pubkey into the recipient's mock store to prepare for a successful JWEDecrypt() for each recipient
	mockStoreMap[senderKIDs[0]] = senderPubKey

	t.Run("Decrypting JWE message test success", func(t *testing.T) {
		jd := ariesjose.NewJWEDecrypt(mockStore, tinkCrypto, k)
		require.NotEmpty(t, jd)

		var msg []byte

		msg, err = jd.Decrypt(localJWE)
		require.NoError(t, err)
		require.EqualValues(t, payloadBytes, msg)
	})

	*/
}
