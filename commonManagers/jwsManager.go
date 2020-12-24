package commonManagers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
	"github.com/btcsuite/btcutil/base58"
	"strings"
)

const (
	Ed25519KeyType 			= "Ed25519VerificationKey2018"
	Ed25519SignatureType 	= "Ed25519Signature2018"
	DidContext             	= "https://www.w3.org/ns/did/v1"
	SecurityContext        	= "https://w3id.org/security/v2"
	SecurityContextJWK2020 	= "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
)

const (
	JwtPartsNumber   = 3
	JwtHeaderPart    = 0
	JwtSignaturePart = 2
)

func CreateEd25519SignKeys() (*models.Ed25519SignerEntity, error) {

	// It generates public and private signing keys for Ed25519Signature2018
	publicSingKeyBytes, secretSignKeyBytes, _ := ed25519.GenerateKey(nil)
	// if err != nil {return nil, err}

	uuidRandomv4, _ := uuid.NewRandom()
	// if err != nil {return nil, err}
	uuidv4String := uuidRandomv4.String()

	signerEntity := &models.Ed25519SignerEntity{
		Id : uuidv4String,
		// UhcKeyIdBase64URL:
		PublicKeyBytes: publicSingKeyBytes,
		PrivateKeyBytes: secretSignKeyBytes,
		PublicKeyBase58: base58.Encode(publicSingKeyBytes),
		PrivateKeyBase58: base58.Encode(secretSignKeyBytes),
		PublicKeyBase64: BytesToBase64String(publicSingKeyBytes),
		PrivateKeyBase64: BytesToBase64String(secretSignKeyBytes),
	}

	return signerEntity, nil
}

func GetJwtHeaderMap (jwtHeaderB64 string) map[string]interface{} {
	jwtHeaderBytes, _ := base64.RawURLEncoding.DecodeString(jwtHeaderB64)

	var jwtHeaderMap map[string]interface{}
	_ = json.Unmarshal(jwtHeaderBytes, &jwtHeaderMap)

	return jwtHeaderMap
}

func GetJWTHeader(jwt string) (string, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != JwtPartsNumber { // nolint:gomnd
		return "", errors.New("invalid JWT")
	}

	return jwtParts[JwtHeaderPart], nil
}

// GetDigest returns document digest.
func DigestForEd25519Signature2018(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
