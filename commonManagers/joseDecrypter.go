package commonManagers

/*
   Copyright SecureKey Technologies Inc. All Rights Reserved.

   SPDX-License-Identifier: Apache-2.0
*/
/*
import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	cryptoapi "github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/jose"

	"github.com/google/tink/go/keyset"

	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	// "github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	// disabled here "github.com/Universal-Health-Chain/aries-framework-go/pkg/storage"
)


// Decrypter interface to deserialize JWE, to extract the corresponding recipient key, and to decrypt and return plaintext
type Decrypter interface {
	Decrypt(jwe *jose.JSONWebEncryption) ([]byte, error)
}

type decPrimitiveFunc func(*keyset.Handle) (api.CompositeDecrypt, error)

// JWEDecrypt for decrypting a JWE message and to return its protected plaintext.
type JWEDecrypt struct {
	recipientKH  *keyset.Handle
	getPrimitive decPrimitiveFunc
}

// NewJWEDecrypt creates a new JWEDecrypt instance to parse and decrypt a JWE message for a given recipient
func NewJWEDecrypt(recipientKH *keyset.Handle) *JWEDecrypt {
	return &JWEDecrypt{
		recipientKH:  recipientKH,
		getPrimitive: getECDHESDecPrimitive,
		// store:	store,	// disabled here
	}
}

func getECDHESDecPrimitive(recipientKH *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdhes.NewECDHESDecrypt(recipientKH)
}

func getECDH1PUDecPrimitive(recipientKH *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdh.NewECDH1PUDecrypt(recipientKH)
}

// Decrypt a deserialized JWE, decrypts its protected content and returns plaintext.
func (jd *JWEDecrypt) Decrypt(jwe *jose.JSONWebEncryption) ([]byte, error) {
	var (
		err              error
		protectedHeaders jose.Headers
		encAlg           string
		encType          string
	)

	protectedHeaders, encAlg, encType, err = jd.validateAndExtractProtectedHeaders(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	skid, ok := protectedHeaders.SenderKeyID()
	if ok {
		err = jd.addSenderKey(skid)
		if err != nil {
			return nil, fmt.Errorf("jwedecrypt: failed to add sender key: %w", err)
		}

		jd.getPrimitive = getECDH1PUDecPrimitive
	}

	decPrimitive, err := jd.getPrimitive(jd.recipientKH)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to get decryption primitive: %w", err)
	}

	encryptedData, err := buildEncryptedData(encAlg, encType, jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build encryptedData for Decrypt(): %w", err)
	}

	authData, err := computeAuthData(protectedHeaders, []byte(jwe.AAD))	// computeAuthData is in joseEncrypter.go
	if err != nil {
		return nil, err
	}

	if len(jwe.Recipients) == 1 {
		authData = []byte(jwe.OrigProtectedHders)
	}

	return decPrimitive.Decrypt(encryptedData, authData)
}

// it gets the public key not from Aries store but from models.GetPublicEncryptionKeyByUserID()
func (jd *JWEDecrypt) fetchSenderPubKey(publicSenderKeyB58 string) (*composite.PublicKey, error) {
	var keyManager KeyPairManager	// It creates the required manager
	return keyManager.GetPublicCompositeKeyByBase58(&publicSenderKeyB58)
}

// management of user public keys does not use Aries store
func (jd *JWEDecrypt) addSenderKey(skid string) error {
	var senderPubKey *composite.PublicKey

	// addSenderKey requires the store where to fetch the sender public key
	// if jd.store == nil { return errors.New("unable to decrypt JWE with 'skid' header, third party key store is nil") }

	senderPubKey, err := jd.fetchSenderPubKey(skid)
	if err != nil {
		return err
	}

	jd.recipientKH, err = ecdh1pu.AddSenderKey(jd.recipientKH, senderPubKey)
	if err != nil {
		return err
	}

	return nil
}

func (jd *JWEDecrypt) validateAndExtractProtectedHeaders(jwe *jose.JSONWebEncryption) (jose.Headers, string, string, error) {
	if jwe == nil {
		return nil, "", "", fmt.Errorf("jwe is nil")
	}

	protectedHeaders := jwe.ProtectedHeaders

	encAlg, ok := protectedHeaders.Encryption()
	if !ok {
		return nil, "", "", fmt.Errorf("jwe is missing encryption algorithm 'enc' header")
	}

	// TODO go Jose doesn't set/enforce content `typ` in the protected headers when encrypting. When fixed, remove
	//      the following line and add a check to ensure it's available.
	encType := composite.DIDCommEncType // used by authcrypt/anoncrypt. The jose package is not used by LegacyPacker.

	// TODO add support for Chacha content encryption, issue #1684
	switch encAlg {
	case string(jose.A256GCM):
	default:
		return nil, "", "", fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	return protectedHeaders, encAlg, encType, nil
}

func buildEncryptedData(encAlg, encType string, jwe *jose.JSONWebEncryption) ([]byte, error) {
	var recipients []*cryptoapi.RecipientWrappedKey

	if len(jwe.Recipients) == 1 { // compact serialization: it has only 1 recipient with no headers
		rHeaders, err := extractRecipientHeaders(jwe.ProtectedHeaders)
		if err != nil {
			return nil, err
		}

		rec, err := convertMarshalledJWKToRecKey(rHeaders.EPK)
		if err != nil {
			return nil, err
		}

		rec.KID = rHeaders.KID
		rec.Alg = rHeaders.Alg
		rec.EncryptedCEK = []byte(jwe.Recipients[0].EncryptedKey)

		recipients = []*composite.RecipientWrappedKey{
			rec,
		}
	} else { // full serialization
		for _, recJWE := range jwe.Recipients {
			rec, err := convertMarshalledJWKToRecKey(recJWE.Header.EPK)
			if err != nil {
				return nil, err
			}

			rec.KID = recJWE.Header.KID
			rec.Alg = recJWE.Header.Alg
			rec.EncryptedCEK = []byte(recJWE.EncryptedKey)

			recipients = append(recipients, rec)
		}
	}

	encData := new(composite.EncryptedData)
	encData.Recipients = recipients
	encData.Tag = []byte(jwe.Tag)
	encData.IV = []byte(jwe.IV)
	encData.Ciphertext = []byte(jwe.Ciphertext)
	encData.EncAlg = encAlg
	encData.EncType = encType

	return json.Marshal(encData)
}

// extractRecipientHeaders will extract RecipientHeaders from headers argument.
func extractRecipientHeaders(headers map[string]interface{}) (*jose.RecipientHeaders, error) {
	// Since headers is a generic map, epk value is converted to a generic map by Serialize(), ie we lose RawMessage
	// type of epk. We need to convert epk value (generic map) to marshaled json so we can call RawMessage.Unmarshal()
	// to get the original epk value (RawMessage type).
	mapData, ok := headers[jose.HeaderEPK].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("JSON value is not a map (%#v)", headers[jose.HeaderEPK])
	}

	epkBytes, err := json.Marshal(mapData)
	if err != nil {
		return nil, err
	}

	epk := json.RawMessage{}

	err = epk.UnmarshalJSON(epkBytes)
	if err != nil {
		return nil, err
	}

	alg := ""
	if headers[jose.HeaderAlgorithm] != nil {
		alg = fmt.Sprintf("%v", headers[jose.HeaderAlgorithm])
	}

	kid := ""
	if headers[jose.HeaderKeyID] != nil {
		kid = fmt.Sprintf("%v", headers[jose.HeaderKeyID])
	}

	recHeaders := &jose.RecipientHeaders{
		Alg: alg,
		KID: kid,
		EPK: epk,
	}

	// now delete from headers
	delete(headers, jose.HeaderAlgorithm)
	delete(headers, jose.HeaderKeyID)
	delete(headers, jose.HeaderEPK)

	return recHeaders, nil
}

func convertMarshalledJWKToRecKey(marshalledJWK []byte) (*composite.RecipientWrappedKey, error) {
	jwk := &jose.JWK{}

	err := jwk.UnmarshalJSON(marshalledJWK)
	if err != nil {
		return nil, err
	}

	epk := composite.PublicKey{
		Curve: jwk.Crv,
		Type:  jwk.Kty,
	}

	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		epk.X = key.X.Bytes()
		epk.Y = key.Y.Bytes()
	default:
		return nil, fmt.Errorf("unsupported recipient key type")
	}

	return &composite.RecipientWrappedKey{
		KID: jwk.KeyID,
		EPK: epk,
	}, nil

}
 */
