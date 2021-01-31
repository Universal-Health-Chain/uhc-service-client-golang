package commonManagers
/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"

	gojosev3 "github.com/square/go-jose/v3"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
)

type EncAlg string	// it represents the JWE content encryption algorithm
const A256GCM = EncAlg(composite.A256GCM)	// for AES256GCM content encryption

// Encrypter interface to Encrypt/Decrypt JWE messages
type Encrypter interface {
	// Non repudiable signature
	EncryptWithAuthData(plaintext, aad []byte) (*jose.JSONWebEncryption, error) // (encrypt plaintext and aad sent to more than 1 recipients)

	// Encrypt plaintext with empty aad sent to 1 or more recipients and returns a valid JSONWebEncryption instance
	Encrypt(plaintext []byte) (*jose.JSONWebEncryption, error)
}

type encPrimitiveFunc func(*keyset.Handle) (api.CompositeEncrypt, error)

// JWEEncrypt is responsible for encrypting a plaintext and its AAD into a protected JWE and decrypting it.
type JWEEncrypt struct {
	recipients   []*composite.PublicKey
	skid         string
	senderKH     *keyset.Handle
	getPrimitive encPrimitiveFunc
	encAlg       EncAlg
	encTyp       string
}

// NewJWEEncrypt creates a new JWEEncrypt instance to build JWE with recipientsPubKeys
// senderKID and senderKH are used for Authcrypt (to authenticate the sender), if not set JWEEncrypt assumes Anoncrypt.
func NewJWEEncrypt(encAlg EncAlg, encType, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*composite.PublicKey) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("empty recipientsPubKeys list")
	}

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case A256GCM:
	default:
		return nil, fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	// ECDH-ES does not reveal the sender's key (ie anoncrypt)
	primitiveFunc := getECDHESEncPrimitive

	if senderKH != nil {
		// senderKID is required with non empty senderKH
		if senderKID == "" {
			return nil, errors.New("senderKID is required with senderKH")
		}

		// ECDH-1PU reveals the sender's key (ie authcrypt)
		primitiveFunc = getECDH1PUEncPrimitive
	}

	var err error

	senderKH, err = getHandle(senderKH, recipientsPubKeys)
	if err != nil {
		return nil, err
	}

	return &JWEEncrypt{
		recipients:   recipientsPubKeys,
		skid:         senderKID,
		senderKH:     senderKH,
		getPrimitive: primitiveFunc,
		encAlg:       encAlg,
		encTyp:       encType,
	}, nil
}

func getHandle(senderKH *keyset.Handle, recipientsPubKeys []*composite.PublicKey) (*keyset.Handle, error) {
	if senderKH != nil {
		return ecdh1pu.AddRecipientsKeys(senderKH, recipientsPubKeys)
	}

	// empty senderPubKey means Anoncrypt encryption (ie sender identity is anonymous),
	// create a new ECDHES key as senderPubKey
	kt, err := ecdhes.ECDHES256KWAES256GCMKeyTemplateWithRecipients(recipientsPubKeys)
	if err != nil {
		return nil, err
	}

	return keyset.NewHandle(kt)
}

func getECDHESEncPrimitive(senderKH *keyset.Handle) (api.CompositeEncrypt, error) {
	senderPubKH, err := senderKH.Public()
	if err != nil {
		return nil, err
	}

	return ecdhes.NewECDHESEncrypt(senderPubKH)
}

func getECDH1PUEncPrimitive(senderKH *keyset.Handle) (api.CompositeEncrypt, error) {
	senderPubKH, err := senderKH.Public()
	if err != nil {
		return nil, err
	}

	return ecdh1pu.NewECDH1PUEncrypt(senderPubKH)
}

// Encrypt encrypt plaintext with AAD and returns a JSONWebEncryption instance to serialize a JWE instance.
func (je *JWEEncrypt) Encrypt(plaintext []byte) (*jose.JSONWebEncryption, error) {
	return je.EncryptWithAuthData(plaintext, nil)
}

// EncryptWithAuthData encrypt plaintext with AAD and returns a JSONWebEncryption instance to serialize a JWE instance.
func (je *JWEEncrypt) EncryptWithAuthData(plaintext, aad []byte) (*jose.JSONWebEncryption, error) {
	encPrimitive, err := je.getPrimitive(je.senderKH)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to get encryption primitive: %w", err)
	}

	protectedHeaders := map[string]interface{}{
		models.HeaderEncryption: je.encAlg,
		models.HeaderType:       je.encTyp,
	}

	if je.skid != "" {
		protectedHeaders[models.HeaderSenderKeyID] = je.skid
	}

	authData, err := computeAuthData(protectedHeaders, aad)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: computeAuthData: marshal error %w", err)
	}

	serializedEncData, err := encPrimitive.Encrypt(plaintext, authData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to Encrypt: %w", err)
	}

	encData := new(composite.EncryptedData)

	err = json.Unmarshal(serializedEncData, encData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: unmarshal encrypted data failed: %w", err)
	}

	recipients, singleRecipientHeaders, err := je.buildRecipients(encData)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to build recipients: %w", err)
	}

	if singleRecipientHeaders != nil {
		mergeRecipientHeaders(protectedHeaders, singleRecipientHeaders)
	}

	jsonEncryption := &jose.JSONWebEncryption{
		IV:               string(encData.IV),
		Tag:              string(encData.Tag),
		Ciphertext:       string(encData.Ciphertext),
		Recipients:       recipients,
		ProtectedHeaders: protectedHeaders,
		AAD:              string(aad),
	}

	return jsonEncryption, nil
}

func mergeRecipientHeaders(headers map[string]interface{}, recHeaders *jose.RecipientHeaders) {
	headers[models.HeaderAlgorithm] = recHeaders.Alg
	headers[models.HeaderKeyID] = recHeaders.KID

	// EPK will be marshalled by Serialize
	headers[models.HeaderEPK] = recHeaders.EPK
}

func (je *JWEEncrypt) buildRecipients(encData *composite.EncryptedData) ([]*jose.Recipient, *jose.RecipientHeaders, error) {
	var (
		recipients             []*jose.Recipient
		singleRecipientHeaders *jose.RecipientHeaders
	)

	for _, rec := range encData.Recipients {
		recHeaders, err := buildRecipientHeaders(rec)
		if err != nil {
			return nil, nil, err
		}

		recipients = append(recipients, &jose.Recipient{
			EncryptedKey: string(rec.EncryptedCEK),
			Header:       recHeaders,
		})
	}

	// if we have only 1 recipient, then assume compact JWE serialization format. This means recipient header should
	// be merged with the JWE envelope's protected headers and not added to the recipients
	if len(encData.Recipients) == 1 {
		singleRecipientHeaders = &jose.RecipientHeaders{
			Alg: recipients[0].Header.Alg,
			KID: recipients[0].Header.KID,
			EPK: recipients[0].Header.EPK,
		}

		recipients[0].Header = nil
	}

	return recipients, singleRecipientHeaders, nil
}

func buildRecipientHeaders(rec *composite.RecipientWrappedKey) (*jose.RecipientHeaders, error) {
	mRecJWK, err := convertRecKeyToMarshalledJWK(rec)
	if err != nil {
		return nil, fmt.Errorf("failed to convert recipient key to marshalled JWK: %w", err)
	}

	return &jose.RecipientHeaders{
		KID: rec.KID,
		Alg: rec.Alg,
		EPK: mRecJWK,
	}, nil
}

func convertRecKeyToMarshalledJWK(rec *composite.RecipientWrappedKey) ([]byte, error) {
	var c elliptic.Curve

	c, err := hybrid.GetCurve(rec.EPK.Curve)
	if err != nil {
		return nil, err
	}

	recJWK := jose.JWK{
		JSONWebKey: gojosev3.JSONWebKey{
			KeyID: rec.KID,
			Use:   models.HeaderEncryption,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(rec.EPK.X),
				Y:     new(big.Int).SetBytes(rec.EPK.Y),
			},
		},
		Kty: "EC", // TODO add support for X25519 content encryption, issue #1684
		Crv: rec.EPK.Curve,
	}

	return recJWK.MarshalJSON()
}

// Get the additional authenticated data from a JWE object.
func computeAuthData(protectedHeaders map[string]interface{}, aad []byte) ([]byte, error) {
	var protected string

	if protectedHeaders != nil {
		protectedHeadersJSON := map[string]json.RawMessage{}

		for k, v := range protectedHeaders {
			mV, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}

			rawMsg := json.RawMessage(mV) // need to explicitly convert []byte to RawMessage (same as go-jose)
			protectedHeadersJSON[k] = rawMsg
		}

		mProtected, err := json.Marshal(protectedHeadersJSON)
		if err != nil {
			return nil, err
		}

		protected = base64.RawURLEncoding.EncodeToString(mProtected)
	} else {
		protected = ""
	}

	output := []byte(protected)
	if len(aad) > 0 {
		output = append(output, '.')

		encLen := base64.RawURLEncoding.EncodedLen(len(aad))
		aadEncoded := make([]byte, encLen)

		base64.RawURLEncoding.Encode(aadEncoded, aad)
		output = append(output, aadEncoded...)
	}

	return output, nil
}

