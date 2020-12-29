package commonManagers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"strings"
	"time"
)

const (
	JwtPartsNumber   = 3
	JwtHeaderPart    = 0
	JwtSignaturePart = 2
)

func SignJsonWithProofJWS(signKeyPair models.Key, serializedJson string, purpose string) ([]byte, error) {
	privateSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)
	if err != nil || privateSignKeyBytes == nil {return nil, errors.New("No valid KeyPair")}

	publicSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)
	if err != nil || publicSignKeyBytes == nil {return nil, errors.New("No valid KeyPair")}

	// TODO: check if purpose is valid

	signerEntity := signature.GetEd25519Signer(privateSignKeyBytes, publicSignKeyBytes)
	proofCreator := signKeyPair.Controller

	s := documentSigner.New(ed25519signature2018.New(suite.WithSigner(signerEntity)))

	signContext := &documentSigner.Context{
		SignatureType:           Ed25519SignatureType,
		Creator:                 proofCreator,
		SignatureRepresentation: 0,
		Created:                 &time.Time{},
		Domain:                  "",
		Nonce:                   nil,
		VerificationMethod:      "",
		Challenge:               "",
		Purpose:                 purpose,
	}

	// Only for testing
	signedDoc, err := s.Sign(signContext, []byte(serializedJson))
	if err != nil {return nil, err}
	println("signedDoc = ", string(signedDoc))

	// It creates the desired 'jws' field instead of 'proofValue'
	signContext.SignatureRepresentation = proof.SignatureJWS
	signedJWSDoc, err := s.Sign(signContext, []byte(serializedJson))
	if err != nil {return nil, err}

	println("signedJWSDoc = ", string(signedJWSDoc))
	return signedJWSDoc, err
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

func DocDigestForEd25519Signature2018(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
