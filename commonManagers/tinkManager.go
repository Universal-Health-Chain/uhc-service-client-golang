package commonManagers

// For creating keys: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
// KEK (Key Encription Key) is in remote KMS. DEK (Database-Encryption Key) is encripted with KEK in the local database.
// There are two keys between the user and the data: the database-encryption key (DEK) or column-encryption key (CEK)
// Some concepts: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/teserakt-io/golang-ed25519/extra25519"

	"github.com/Universal-Health-Chain/aries-framework-go/pkg/secretlock/noop"

	"encoding/base64"
	"fmt"
	"strings"
	"github.com/google/tink/go/tink"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/secretlock"
)

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// LocalKeyURIPrefix for locally stored keys.
const LocalKeyURIPrefix = "local-lock://"

// LocalAEAD represents a local kms aead service invoking a local SecretLock to a particular key URI.
// Instances of LocalAEAD are invoked internally by Tink for wrapping/unwrapping keys. It must not
// be used elsewhere.
type LocalAEAD struct {
	keyURI     string
	secretLock secretlock.Service
}

// New creates a new key wrapper with the given uriPrefix and a local secretLock service.
func New(secretLock secretlock.Service, keyURI string) (tink.AEAD, error) {
	if !strings.HasPrefix(strings.ToLower(keyURI), LocalKeyURIPrefix) || len(keyURI) <= len(LocalKeyURIPrefix) {
		return nil, fmt.Errorf("keyURI must start with %s", LocalKeyURIPrefix)
	}

	uri := strings.TrimPrefix(keyURI, LocalKeyURIPrefix)

	return &LocalAEAD{
		keyURI:     uri,
		secretLock: secretLock,
	}, nil
}

// Encrypt LocalAEAD encrypts plaintext with addtionaldata.
func (a *LocalAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	req := &secretlock.EncryptRequest{
		Plaintext:                   base64.URLEncoding.EncodeToString(plaintext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Encrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	ct, err := base64.URLEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// Decrypt LocalAEAD decrypts the data and verified the additional data.
func (a *LocalAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	req := &secretlock.DecryptRequest{
		Ciphertext:                  base64.URLEncoding.EncodeToString(ciphertext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Decrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	pt, err := base64.URLEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

// from Aries kms local cryptobox

// exportEncPrivKeyBytes temporary support function for crypto_box to be used with legacyPacker only.
func ExportEncPrivKeyBytes(id string) ([]byte, error) {
	// kh, err := l.getKeySet(id)
	var keyManager KeyPairManager
	kh, err := keyManager.CreateAuthcryptKeysetHandle()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	bWriter := keyset.NewBinaryWriter(buf)

	kw, err := New(&noop.NoLock{}, "local-lock://tmp")
	if err != nil {
		return nil, err
	}

	primaryKeyEnvAEAD := aead.NewKMSEnvelopeAEAD(*aead.AES256GCMKeyTemplate(), kw)

	err = kh.Write(bWriter, primaryKeyEnvAEAD)
	if err != nil {
		return nil, err
	}

	encryptedKS := &tinkpb.EncryptedKeyset{}

	err = proto.Unmarshal(buf.Bytes(), encryptedKS)
	if err != nil {
		return nil, err
	}

	decryptedKS, err := primaryKeyEnvAEAD.Decrypt(encryptedKS.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, err
	}

	return ExtractPrivKey(decryptedKS)
}

func ExtractPrivKey(marshalledKeySet []byte) ([]byte, error) {
	ks := &tinkpb.Keyset{}

	err := proto.Unmarshal(marshalledKeySet, ks)
	if err != nil {
		return nil, err
	}

	for _, key := range ks.Key {
		if key.KeyId != ks.PrimaryKeyId || key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}

		prvKey := &ed25519pb.Ed25519PrivateKey{}

		err = proto.Unmarshal(key.KeyData.Value, prvKey)
		if err != nil {
			return nil, err
		}

		pkBytes := make([]byte, ed25519.PrivateKeySize)
		copy(pkBytes[:ed25519.PublicKeySize], prvKey.KeyValue)
		copy(pkBytes[ed25519.PublicKeySize:], prvKey.PublicKey.KeyValue)

		return SecretEd25519toCurve25519(pkBytes)
	}

	return nil, errors.New("private key not found")
}

// Curve25519KeySize number of bytes in a Curve25519 public or private key.
const Curve25519KeySize = 32

// NonceSize size of a nonce used by Box encryption (Xchacha20Poly1305).
const NonceSize = 24

// SecretEd25519toCurve25519 converts a secret key from Ed25519 to curve25519 format
// This function wraps PrivateKeyToCurve25519 from Adam Langley's ed25519 repo: https://github.com/agl/ed25519 now
// moved to https://github.com/teserakt-io/golang-ed25519
func SecretEd25519toCurve25519(priv []byte) ([]byte, error) {
	if len(priv) == 0 {
		return nil, errors.New("private key is nil")
	}

	sKIn := new([ed25519.PrivateKeySize]byte)
	copy(sKIn[:], priv)

	sKOut := new([Curve25519KeySize]byte)
	extra25519.PrivateKeyToCurve25519(sKOut, sKIn)

	return sKOut[:], nil
}

// ErrKeyNotFound is returned when key not found.
var ErrKeyNotFound = errors.New("key not found")

// ErrInvalidKey is used when a key is invalid.
var ErrInvalidKey = errors.New("invalid key")
