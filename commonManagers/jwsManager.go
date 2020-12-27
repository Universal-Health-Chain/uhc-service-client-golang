package commonManagers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"strings"
)

const (
	X25519KeyType 			= "X25519KeyAgreementKey2019"
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

func SignJsonWithProofJWS(signerEntity signature.Signer, serializedJson string, proofCreator string) ([]byte, error) {
	s := documentSigner.New(ed25519signature2018.New(suite.WithSigner(signerEntity)))

	signContext := &documentSigner.Context{
		Creator:       proofCreator,
		SignatureType: Ed25519SignatureType,
	}

	signedDoc, err := s.Sign(signContext, []byte(serializedJson))
	if err != nil {return nil, err}
	println("signedDoc = ", string(signedDoc))

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

// GetDigest returns document digest.
func DigestForEd25519Signature2018(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}
