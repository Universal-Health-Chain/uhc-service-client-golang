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

func CreateEd25519SignKeys() (*models.Ed25519SignerEntity, error) {

	// It generates public and private signing keys for Ed25519Signature2018
	publicSingKeyBytes, secretSignKeyBytes, _ := ed25519.GenerateKey(nil)
	// if err != nil {return nil, err}

	uuidRandom, _ := uuid.NewRandom()
	// if err != nil {return nil, err}
	id := uuidRandom.String()

	signerEntity := &models.Ed25519SignerEntity{
		Id : id,
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
	if len(jwtParts) != jwtPartsNumber { // nolint:gomnd
		return "", errors.New("invalid JWT")
	}

	return jwtParts[jwtHeaderPart], nil
}

// GetDigest returns document digest.
func DigestForEd25519Signature2018(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
