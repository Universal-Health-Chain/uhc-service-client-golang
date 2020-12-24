package commonManagers

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateVerifyDataOfChallenge(t *testing.T){
	signer := signature.GetEd25519Signer([]byte(issuerPrivKey), []byte(issuerPubKey))
	signSuite := ed25519signature2018.New(suite.WithSigner(signer))

	proofOptions := &proof.Proof{
		Type: ed25519signature2018.SignatureType,
		SignatureRepresentation: proof.SignatureJWS,
	}

	verifyData, err := CreateVerifyDataOfChallenge(signSuite, "test-challenge-uuid", proofOptions)
	require.NoError(t, err)
	require.NotEmpty(t, verifyData)
	fmt.Printf("verifyData %v \n", string(verifyData))
	fmt.Println(string(verifyData))
}

func getSignatureContext() *signer.Context {
	return &signer.Context{
		Creator:       "creator",
		SignatureType: ed25519signature2018.SignatureType,
	}
}

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyDataOfChallenge(signSuite *ed25519signature2018.Suite, challenge string, proofOptions *proof.Proof) ([]byte, error) {
	if proofOptions.SignatureRepresentation != proof.SignatureJWS {
		return nil, fmt.Errorf("unsupported signature representation")
	}
	return CreateVerifyJWSByString(signSuite, challenge, proofOptions)
}

// CreateVerifyJWSByString creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func CreateVerifyJWSByString(signSuite *ed25519signature2018.Suite, challenge string, p *proof.Proof) ([]byte, error) {
	proofOptions := p.JSONLdObject()
	canonicalProofOptions, err := prepareJWSProof(signSuite, proofOptions) //, opts...)
	if err != nil { return nil, err}

	// proofOptionsDigest := ed25519signature2018.Suite.GetDigest(canonicalProofOptions)
	// canonicalDoc, err := prepareDocumentForJWS(signSuite, challenge) // , opts...)
	// if err != nil { return nil, err }

	proofOptionsDigest := DigestForEd25519Signature2018(canonicalProofOptions)
	challengeDigest := DigestForEd25519Signature2018([]byte(challenge))
	verifyData := append(proofOptionsDigest, challengeDigest...)

	jwtHeader, err := GetJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

const jsonldContext = "@context"
const jsonldProofValue = "proofValue"
const jsonldJWS = "jws"

func prepareJWSProof(signSuite *ed25519signature2018.Suite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions[jsonldContext] = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions { proofOptionsCopy[key] = value }

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofValue)
	canonicalProof, err := signSuite.GetCanonicalDocument(proofOptionsCopy, nil) // , opts...)
	return canonicalProof, err
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	var contextMap map[string]interface{}

	err := json.Unmarshal([]byte(SecurityJSONLDSchema), &contextMap)
	if err != nil {
		return nil, err
	}

	return jsonld.Default().Compact(docMap, contextMap, opts...)
}

