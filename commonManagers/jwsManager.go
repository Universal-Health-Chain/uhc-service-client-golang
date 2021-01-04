package commonManagers

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	jcsProof "github.com/Universal-Health-Chain/JcsEd25519Signature2020/signature-suite-impls/golang/proof"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	signerDocument "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	signVerifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	josejwt "github.com/square/go-jose/v3/jwt"
	"strings"
	"time"
)

const (
	SignatureEdDSA = "EdDSA"	// signatureEdDSA defines EdDSA alg.
	JwtPartsNumber   = 3
	JwtHeaderPart    = 0
	JwtSignaturePart = 2
)

type GenericJsonProvableWithJCS struct {
	Data  map[string]interface{}
	Proof jcsProof.Proof `json:"proof"`
}

func (gp *GenericJsonProvableWithJCS) GetProof() *jcsProof.Proof {
	return &gp.Proof
}

func (gp *GenericJsonProvableWithJCS) SetProof(p jcsProof.Proof) {
	gp.Proof = p
}

func SignWithJcs2020Proof(jsonSerialized string, signKeyPair models.Key) ([]byte, error){
	privateSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)
	if err != nil || privateSignKeyBytes == nil {return nil, errors.New("No valid KeyPair")}

	var data map[string]interface{}
	err = json.Unmarshal([]byte(jsonSerialized), &data)
	if err != nil {return nil, errors.New("No valid JSON to sign")}

	provable := GenericJsonProvableWithJCS{
		Data: data,
		Proof: jcsProof.Proof{ Type: jcsProof.JCSSignatureType },
	}

	signedDocBytes, err := jcsProof.GenericSign(&provable, privateSignKeyBytes)
	if err != nil {return nil, errors.New("Error signing with Ed25519 private key")}

	return signedDocBytes, nil
}

func GetKeyResolver(pubKey *signVerifier.PublicKey, err error) jwt.KeyResolver {
	return jwt.KeyResolverFunc(func(string, string) (*signVerifier.PublicKey, error) {
		return pubKey, err
	})
}
func BuildJWS(signer jose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

func VerifyEd25519ViaGoJose(jws string, pubKey ed25519.PublicKey, claims interface{}) (bool, error) {
	jwtToken, err := josejwt.ParseSigned(jws)
	if err != nil {
		return false, fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	err = jwtToken.Claims(pubKey, claims)
	if err != nil {
		return false, fmt.Errorf("verify JWT signature: %w", err)
	}

	return true, nil
}

/*
	Ed25519Signature2018 signature suite for the Linked Data Signatures [LD-SIGNATURES] specification.
	It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION] to transform the input document into its canonical form.
	It uses SHA-256 [RFC6234] as the message digest algorithm and Ed25519 [ED25519] as the signature algorithm.
	https://godoc.org/github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018
*/
func SignWithAriesProof(signKeyPair models.Key, serializedJson string, jws bool, purpose string) ([]byte, error) {
	privateSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)
	if err != nil || privateSignKeyBytes == nil {return nil, errors.New("No valid KeyPair")}

	publicSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)
	if err != nil || publicSignKeyBytes == nil {return nil, errors.New("No valid KeyPair")}

	// TODO: check if purpose is valid

	signerEntity := signature.GetEd25519Signer(privateSignKeyBytes, publicSignKeyBytes)
	ariesDocSigner := signerDocument.New(ed25519signature2018.New(suite.WithSigner(signerEntity)))

	signContext := &signerDocument.Context{
		SignatureType:           Ed25519SignatureType,
		Creator:                 signKeyPair.PublicKeyDID,	// Public DID Verification Key of the creator of the signature
		Created:                 &time.Time{},
		Domain:                  "",
		Nonce:                   nil,
		VerificationMethod:      "",
		Challenge:               "",
		Purpose:                 purpose,
	}

	signedDoc := []byte("")	// initializes signedDoc
	if jws == false {
		// It creates the proof with 'proofValue'
		signedDoc, err = ariesDocSigner.Sign(signContext, []byte(serializedJson))
		if err != nil {return nil, err}
	} else {
		// It creates the proof with 'jws' field instead of 'proofValue'
		signContext.SignatureRepresentation = proof.SignatureJWS
		signedDoc, err = ariesDocSigner.Sign(signContext, []byte(serializedJson))
		if err != nil {return nil, err}
	}

	return signedDoc, err
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
