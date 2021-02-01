package commonManagers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	// "github.com/google/tink/go/aead"
	// "github.com/google/tink/go/mac"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	// "github.com/google/tink/go/signature"
	// "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	// "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	"strings"
	// "github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	// "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	// "github.com/hyperledger/aries-framework-go/pkg/kms"
	// "github.com/hyperledger/aries-framework-go/pkg/storage"
)

/* TODO: clean tests */

// Package authcrypt includes a Packer implementation to build and parse JWE messages using Authcrypt. It allows sending
// messages between parties with non-repudiation messages, ie the sender identity is revealed (and therefore
// authenticated) to the recipient(s). The assumption of using this package is that public keys exchange has previously
// occurred between the sender and the recipient(s).

const (
	encodingType = "didcomm-envelope-enc"
	// ThirdPartyKeysDB is a store name containing keys of third party agents.
	ThirdPartyKeysDB = "thirdpartykeysdb"
	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

// ErrDataNotFound is returned when data not found.
var ErrDataNotFound = errors.New("data not found")

// ErrKeyRequired is returned when key is mandatory.
var ErrKeyRequired = errors.New("key is mandatory")

// var logger = log.New("aries-framework/pkg/didcomm/packer/authcrypt")

// PackMessage Pack a message for one or more recipients.
func PackMessage(messageEnvelope *transport.Envelope) ([]byte, error) {
	if messageEnvelope == nil {
		return nil, errors.New("packMessage: envelope argument is nil")
	}

	var recipients [][]byte
	for _, verKey := range messageEnvelope.ToKeys {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/749 It is possible to have
		//  different key schemes in an interop situation
		// there is no guarantee that each recipient is using the same key types
		// for now this package uses Ed25519 signing keys. Other key schemes should have their own
		// envelope implementations.
		// decode base58 ver key
		verKeyBytes := base58.Decode(verKey)
		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}

	// TODO find a way to dynamically select a packer based on FromKey, recipients and their types.
	//      https://github.com/hyperledger/aries-framework-go/issues/1112 Configurable packing
	basePackager := &authcrypt.Packer{}

	// Packer is an Aries envelope packer/unpacker to support secure DIDComm exchange of envelopes between Aries agents.
	bytes, err := basePackager.Pack(messageEnvelope.Message, messageEnvelope.FromKey, recipients)
	if err != nil {
		return nil, fmt.Errorf("packMessage: failed to pack: %w", err)
	}

	return bytes, nil
}

// DIDComm packager UnpackMessage
func UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	// encType, err := getEncodingType(encMessage)
	// if err != nil { return nil, fmt.Errorf("getEncodingType: %w", err) }

	basePackager := &authcrypt.Packer{}
	envelope, err := basePackager.Unpack(encMessage)
	if err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	//	ignore error - agents can communicate without using DIDs - for example, in DIDExchange
	theirDID, err := GetDID(base58.Encode(envelope.FromKey))
	// ignore error - at beginning of DIDExchange, you might be about to generate a DID
	myDID, err := GetDID(base58.Encode(envelope.ToKey))

	envelope.ToDID = myDID
	envelope.FromDID = theirDID

	return envelope, nil
}

// GetDID gets the DID stored under the given key.
func GetDID(key string) (string, error) {
	return "did:v1:uuid:test", nil
}

type envelopeStub struct {
	Protected string `json:"protected,omitempty"`
}

type headerStub struct {
	Type string `json:"typ,omitempty"`
	SKID string `json:"skid,omitempty"`
}

const authSuffix = "-authcrypt"

func getEncodingType(encMessage []byte) (string, error) {
	env := &envelopeStub{}

	if strings.HasPrefix(string(encMessage), "{") { // full serialized
		err := json.Unmarshal(encMessage, env)
		if err != nil {
			return "", fmt.Errorf("parse envelope: %w", err)
		}
	} else { // compact serialized
		env.Protected = strings.Split(string(encMessage), ".")[0]
	}

	var protBytes []byte

	protBytes1, err1 := base64.URLEncoding.DecodeString(env.Protected)
	protBytes2, err2 := base64.RawURLEncoding.DecodeString(env.Protected)

	switch {
	case err1 == nil:
		protBytes = protBytes1
	case err2 == nil:
		protBytes = protBytes2
	default:
		return "", fmt.Errorf("decode header: %w", err1)
	}

	prot := &headerStub{}

	err := json.Unmarshal(protBytes, prot)
	if err != nil {
		return "", fmt.Errorf("parse header: %w", err)
	}

	packerID := prot.Type

	if prot.SKID != "" {
		// since Type protected header is the same for authcrypt and anoncrypt, the differentiating factor is SKID.
		// If it is present, then it's authcrypt.
		packerID += authSuffix
	}

	return packerID, nil
}


// Packer represents an Authcrypt Pack/Unpacker that outputs/reads Aries envelopes.
type Packer struct {
	// kms    KeyManager
	encAlg jose.EncAlg
	// store  storage.Store
}

func getKID(i int, jwe *jose.JSONWebEncryption) (string, error) {
	var kid string

	if i == 0 && len(jwe.Recipients) == 1 { // compact serialization, recipient headers are in jwe.ProtectedHeaders
		ok := false

		kid, ok = jwe.ProtectedHeaders.KeyID()
		if !ok {
			return "", fmt.Errorf("single recipient missing 'KID' in jwe.ProtectHeaders")
		}
	} else {
		kid = jwe.Recipients[i].Header.KID
	}

	return kid, nil
}


//case ECDSAP521TypeDER:

func createECDSAIEEE1363KeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {
	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
	}
	format := &ecdsapb.EcdsaKeyFormat{Params: params}
	serializedFormat, _ := proto.Marshal(format) //nolint:errcheck

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
/*
// nolint:gocyclo,funlen
func getKeyTemplate(keyType KeyType) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case AES128GCMType:
		return aead.AES128GCMKeyTemplate(), nil
	case AES256GCMNoPrefixType:
		// RAW (to support keys not generated by Tink)
		return aead.AES256GCMNoPrefixKeyTemplate(), nil
	case AES256GCMType:
		return aead.AES256GCMKeyTemplate(), nil
	case ChaCha20Poly1305Type:
		return aead.ChaCha20Poly1305KeyTemplate(), nil
	case XChaCha20Poly1305Type:
		return aead.XChaCha20Poly1305KeyTemplate(), nil
	case ECDSAP256TypeDER:
		return signature.ECDSAP256KeyWithoutPrefixTemplate(), nil
	case ECDSAP384TypeDER:
		return signature.ECDSAP384KeyWithoutPrefixTemplate(), nil
		return signature.ECDSAP521KeyWithoutPrefixTemplate(), nil
	case ECDSAP256TypeIEEEP1363:
		// JWS keys should sign using IEEE_P1363 format only (not DER format)
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256), nil
	case ECDSAP384TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA384, commonpb.EllipticCurveType_NIST_P384), nil
	case ECDSAP521TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA512, commonpb.EllipticCurveType_NIST_P521), nil
	case ED25519Type:
		return signature.ED25519KeyWithoutPrefixTemplate(), nil
	case HMACSHA256Tag256Type:
		return mac.HMACSHA256Tag256KeyTemplate(), nil
	case ECDHES256AES256GCMType:
		return ecdhes.ECDHES256KWAES256GCMKeyTemplate(), nil
	case ECDHES384AES256GCMType:
		return ecdhes.ECDHES384KWAES256GCMKeyTemplate(), nil
	case ECDHES521AES256GCMType:
		return ecdhes.ECDHES521KWAES256GCMKeyTemplate(), nil
	case ECDH1PU256AES256GCMType:
		// Keys created by ECDH1PU templates should be used only to be persisted in the  To execute primitives,
		// one must add the sender public key (on the recipient side using ecdh1pu.AddSenderKey()) or the recipient(s)
		// public key(s) (on the sender side using ecdh1pu.AddRecipientsKeys())
		return ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate(), nil
	case ECDH1PU384AES256GCMType:
		return ecdh1pu.ECDH1PU384KWAES256GCMKeyTemplate(), nil
	case ECDH1PU521AES256GCMType:
		return ecdh1pu.ECDH1PU521KWAES256GCMKeyTemplate(), nil
	default:
		return nil, fmt.Errorf("getKeyTemplate: key type '%s' unrecognized", keyType)
	}
}
*/
const (
	// AES128GCM key type value.
	AES128GCM = "AES128GCM"
	// AES256GCMNoPrefix key type value.
	AES256GCMNoPrefix = "AES256GCMNoPrefix"
	// AES256GCM key type value.
	AES256GCM = "AES256GCM"
	// ChaCha20Poly1305 key type value.
	ChaCha20Poly1305 = "ChaCha20Poly1305"
	// XChaCha20Poly1305 key type value.
	XChaCha20Poly1305 = "XChaCha20Poly1305"
	// ECDSAP256DER key type value.
	ECDSAP256DER = "ECDSAP256DER"
	// ECDSAP384DER key type value.
	ECDSAP384DER = "ECDSAP384DER"
	// ECDSAP521DER key type value.
	ECDSAP521DER = "ECDSAP521DER"
	// ECDSAP256IEEEP1363 key type value.
	ECDSAP256IEEEP1363 = "ECDSAP256IEEEP1363"
	// ECDSAP384IEEEP1363 key type value.
	ECDSAP384IEEEP1363 = "ECDSAP384IEEEP1363"
	// ECDSAP521IEEEP1363 key type value.
	ECDSAP521IEEEP1363 = "ECDSAP521IEEEP1363"
	// ECDSASecp256k1IEEEP1363 key type value.
	ECDSASecp256k1IEEEP1363 = "ECDSASecp256k1IEEEP1363"
	// ED25519 key type value.
	ED25519 = "ED25519"
	// RSARS256 key type value.
	RSARS256 = "RSARS256"
	// RSAPS256 key type value.
	RSAPS256 = "RSAPS256"
	// HMACSHA256Tag256 key type value.
	HMACSHA256Tag256 = "HMACSHA256Tag256"
	// ECDHES256AES256GCM key type value.
	ECDHES256AES256GCM = "ECDHES256AES256GCM"
	// ECDHES384AES256GCM key type value.
	ECDHES384AES256GCM = "ECDHES384AES256GCM"
	// ECDHES521AES256GCM key type value.
	ECDHES521AES256GCM = "ECDHES521AES256GCM"
	// ECDH1PU256AES256GCM key type value.
	ECDH1PU256AES256GCM = "ECDH1PU256AES256GCM"
	// ECDH1PU384AES256GCM key type value.
	ECDH1PU384AES256GCM = "ECDH1PU384AES256GCM"
	// ECDH1PU521AES256GCM key type value.
	ECDH1PU521AES256GCM = "ECDH1PU521AES256GCM"
)

// KeyType represents a key type supported by the
type KeyType string

const (
	// AES128GCMType key type value.
	AES128GCMType = KeyType(AES128GCM)
	// AES256GCMNoPrefixType key type value.
	AES256GCMNoPrefixType = KeyType(AES256GCMNoPrefix)
	// AES256GCMType key type value.
	AES256GCMType = KeyType(AES256GCM)
	// ChaCha20Poly1305Type key type value.
	ChaCha20Poly1305Type = KeyType(ChaCha20Poly1305)
	// XChaCha20Poly1305Type key type value.
	XChaCha20Poly1305Type = KeyType(XChaCha20Poly1305)
	// ECDSAP256TypeDER key type value.
	ECDSAP256TypeDER = KeyType(ECDSAP256DER)
	// ECDSAP384TypeDER key type value.
	ECDSAP384TypeDER = KeyType(ECDSAP384DER)
	// ECDSAP521TypeDER key type value.
	ECDSAP521TypeDER = KeyType(ECDSAP521DER)
	// ECDSAP256TypeIEEEP1363 key type value.
	ECDSAP256TypeIEEEP1363 = KeyType(ECDSAP256IEEEP1363)
	// ECDSAP384TypeIEEEP1363 key type value.
	ECDSAP384TypeIEEEP1363 = KeyType(ECDSAP384IEEEP1363)
	// ECDSAP521TypeIEEEP1363 key type value.
	ECDSAP521TypeIEEEP1363 = KeyType(ECDSAP521IEEEP1363)
	// ECDSASecp256k1TypeIEEEP1363 key type value.
	ECDSASecp256k1TypeIEEEP1363 = KeyType(ECDSASecp256k1IEEEP1363)
	// ED25519Type key type value.
	ED25519Type = KeyType(ED25519)
	// RSARS256Type key type value.
	RSARS256Type = KeyType(RSARS256)
	// RSAPS256Type key type value.
	RSAPS256Type = KeyType(RSAPS256)
	// HMACSHA256Tag256Type key type value.
	HMACSHA256Tag256Type = KeyType(HMACSHA256Tag256)
	// ECDHES256AES256GCMType key type value.
	ECDHES256AES256GCMType = KeyType(ECDHES256AES256GCM)
	// ECDHES384AES256GCMType key type value.
	ECDHES384AES256GCMType = KeyType(ECDHES384AES256GCM)
	// ECDHES521AES256GCMType key type value.
	ECDHES521AES256GCMType = KeyType(ECDHES521AES256GCM)
	// ECDH1PU256AES256GCMType key type value.
	ECDH1PU256AES256GCMType = KeyType(ECDH1PU256AES256GCM)
	// ECDH1PU384AES256GCMType key type value.
	ECDH1PU384AES256GCMType = KeyType(ECDH1PU384AES256GCM)
	// ECDH1PU521AES256GCMType key type value.
	ECDH1PU521AES256GCMType = KeyType(ECDH1PU521AES256GCM)
)