package commonManagers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	"strings"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	// "github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	// "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	// "github.com/hyperledger/aries-framework-go/pkg/kms"
	// "github.com/hyperledger/aries-framework-go/pkg/storage"
)

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

// didcomm packager UnpackMessage
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
/*
// Authcrypt: ECDH-1PU key wrapping mode to encrypt for a given list of recipients keys
func PackAuthcryptECDH1PU(messageEnvelope *transport.Envelope) {
	if messageEnvelope == nil {
		return nil, errors.New("packMessage: envelope argument is nil")
	}

	// var keyManager KeyPairManager

	// It creates an array of publicKeys of recipients to encrypt for
	var recipientCompositePublicKeys []*composite.PublicKey
	recipientCompositePublicKeys = append(recipientCompositePublicKeys, recipientCompositePublicKey)

	// It creates an array of Handlers only for testing an array of recipients
	var recipientsPublicKeyHandlers []*keyset.Handle
	recipientsPublicKeyHandlers = append(recipientsPublicKeyHandlers, recipientPublicKH)

	// It creates the JWE message
	mockSenderID := "1234"
	jweEnc, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, composite.DIDCommEncType, mockSenderID, senderPublicKH, recipientCompositePublicKeys)
	require.NoError(t, err)
	require.NotEmpty(t, jweEnc)

	// It encrypts the JWE message: ECDH1PU / authcrypt
	pt := []byte("plaintext payload")
	jwEncrypted, err := jweEnc.Encrypt(pt)
	require.NoError(t, err)

	// It serializes the encrypted JWE message to be sent
	var serializedJWE string
	if len(recipientCompositePublicKeys) == 1 {
		serializedJWE, err = jwEncrypted.CompactSerialize(json.Marshal)
	} else {
		serializedJWE, err = jwEncrypted.FullSerialize(json.Marshal)
	}
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)
	fmt.Printf("Serialized JWE = %v \n", serializedJWE)

	// Now it deserializes the received message
	jweReceived, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	// Test ECDH-1PU decrypt for every recipient
	for i, recKH := range recipientsPublicKeyHandlers {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message test success", i), func(t *testing.T) {
			jd := ariesjose.NewJWEDecrypt(nil, recipientKH)
			require.NotEmpty(t, jd)

			var msg []byte

			msg, err = jd.Decrypt(jweReceived)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}
*/
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

/*
// Unpack will decode the envelope using a standard format.
// It unpacks the packedMsg not for all recipients but only for a sole given recipient (recipientKeys)
func (p *Packer) UnpackByKID(serializedBytes []byte, recipientKID string, recipientKeyBytes []byte) (*transport.Envelope, error) {
	jweReceived, err := jose.Deserialize(string(serializedBytes))
	if err != nil {
		return nil, fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	var senderCompositePublicKey *composite.PublicKey
	err := json.Unmarshal(key, &senderCompositePublicKey)
	if err != nil {
		return nil, err
	}

	// Test ECDH-1PU decrypt for every recipient
	jd := ariesjose.NewJWEDecrypt(nil, recipientKH)
	// require.NotEmpty(t, jd)

	var msg []byte
	msg, err = jd.Decrypt(jweReceived)
	// require.NoError(t, err)
	// require.EqualValues(t, pt, msg)

	// TODO get mapped verKey for the recipient encryption key (kid)
	ecdh1puPubKeyByes, err = exportPubKeyBytes(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Unpack: failed to export public key bytes: %w", err)
	}

	return &transport.Envelope{
		Message: pt,
		ToKey:   ecdh1puPubKeyByes,
	}, nil

	// return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in packedMsg")
}

// CompositeDecrypt will decrypt a `ciphertext` representing a composite encryption with a protected cek for the
// recipient caller of this interface. In order to get the plaintext embedded, this type is configured with the
// recipient key type that will decrypt the embedded cek first. This type is used mainly for repudiation requests where
// the sender identity remains unknown using ECDH-ES key wrapping with an ephemeral sender key.
type CompositeDecrypt interface {
	// Decrypt operation: decrypts ciphertext representing a serialized EncryptedData (mainly extracted from a
	// JWE message) for a given recipient. It extracts the underlying secure material then executes key unwrapping of
	// the cek and the AEAD decrypt primitive.
	// returns resulting plaintext extracted from the serialized object.
	Decrypt(cipherText, additionalData []byte) ([]byte, error)
}

// New will create an Packer instance to 'AuthCrypt' payloads for a given sender and list of recipients keys.
// It will open a store (fetch cached one) that will contain third party keys. This store must be pre-populated with
// the sender key required by a recipient to Unpack a JWE envelope. It is not needed by the sender (as the sender packs
// the envelope with its own key).
// The returned Packer contains all the information required to pack and unpack payloads.

// func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {}
// func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {}

// Pack will encode the payload argument
// Using the protocol defined by the Authcrypt message of Aries RFC 0334
// with the following arguments:
// payload: the payload message that will be protected
// senderID: the key id of the sender (stored in the KMS)
// recipientsPubKeys: public keys.
// func (p *Packer) Pack(payload, senderID []byte, recipientsPubKeys [][]byte) ([]byte, error) {

func (p *Packer) Pack(payload, senderID []byte, kh *keyset.Handle, recipientsPubKeys [][]byte) ([]byte, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("authcrypt Pack: empty recipientsPubKeys")
	}

	recECKeys, err := unmarshalRecipientKeys(recipientsPubKeys)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to convert recipient keys: %w", err)
	}

	// kh, err := p.Get(string(senderID))	// pass KeyHandle in params
	// if err != nil { return nil, fmt.Errorf("authcrypt Pack: failed to get sender key from KMS: %w", err)}

	jweEncrypter, err := jose.NewJWEEncrypt(p.encAlg, encodingType, string(senderID), kh, recECKeys)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to new JWEEncrypt instance: %w", err)
	}

	jwe, err := jweEncrypter.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to encrypt payload: %w", err)
	}

	var s string

	if len(recipientsPubKeys) == 1 {
		s, err = jwe.CompactSerialize(json.Marshal)
	} else {
		s, err = jwe.FullSerialize(json.Marshal)
	}

	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to serialize JWE message: %w", err)
	}

	return []byte(s), nil
}

func unmarshalRecipientKeys(keys [][]byte) ([]*composite.PublicKey, error) {
	var pubKeys []*composite.PublicKey

	for _, key := range keys {
		var ecKey *composite.PublicKey

		err := json.Unmarshal(key, &ecKey)
		if err != nil {
			return nil, err
		}

		pubKeys = append(pubKeys, ecKey)
	}

	return pubKeys, nil
}


// Unpack will decode the envelope using a standard format.
// It unpacks the packedMsg not for all recipients but only for a sole given recipient (recipientKeys)
func (p *Packer) Unpack(packedMsg []byte, recipientKeys *keyset.Handle) (*transport.Envelope, error) {
	jwe, err := jose.Deserialize(string(packedMsg))
	if err != nil {
		return nil, fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	for i := range jwe.Recipients {
		var (
			kid                   string
			kh                    interface{}
			pt, ecdh1puPubKeyByes []byte
		)

		kid, err = getKID(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		// TODO: get publicSignKey By KID (DID KeyID)
		kh, err = p.kms.Get(kid)
		if err != nil {
			if errors.Is(err, ErrDataNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				// logger.Debugf("authcrypt Unpack: recipient keyID not found in KMS: %v%s", kid, retriesMsg)
				fmt.Printf("authcrypt Unpack: recipient keyID not found in KMS: %v%s", kid, retriesMsg)
				continue
			}

			return nil, fmt.Errorf("authcrypt Unpack: failed to get key from kms: %w", err)
		}

		keyHandle, ok := kh.(*keyset.Handle)
		if !ok {
			return nil, fmt.Errorf("authcrypt Unpack: invalid keyset handle")
		}

		jweDecrypter := NewJWEDecrypt(keyHandle)

		pt, err = jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to decrypt JWE packedMsg: %w", err)
		}

		// TODO get mapped verKey for the recipient encryption key (kid)
		ecdh1puPubKeyByes, err = exportPubKeyBytes(keyHandle)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to export public key bytes: %w", err)
		}

		return &transport.Envelope{
			Message: pt,
			ToKey:   ecdh1puPubKeyByes,
		}, nil
	}

	return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in packedMsg")
}

 */

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

func exportPubKeyBytes(keyHandle *keyset.Handle) ([]byte, error) {
	pubKH, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodingType for didcomm.
func (p *Packer) EncodingType() string {
	return encodingType
}
/*
func (p *Packer) CreateKeys(kt KeyType) (string, interface{}, error) {
	if kt == "" {
		return "", nil, fmt.Errorf("failed to create new key, missing key type")
	}

	keyTemplate, err := getKeyTemplate(kt)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to getKeyTemplate: %w", err)
	}

	kh, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to create new keyset handle: %w", err)
	}

	// kID, err := l.storeKeySet(kh, kt)
	// if err != nil { return "", nil, fmt.Errorf("create: failed to store keyset: %w", err) }
	kID := keyset.
	return kID, kh, nil
}*/

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