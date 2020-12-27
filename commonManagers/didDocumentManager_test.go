package commonManagers

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	// "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/key"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const DidEntityForTesting = "did:v1:uuid:EntityDidBlockchainUuid"
const UhcPublicSingKeyIdForTesting = "UhcPublicSingKeyId"
const DidCreatorForTesting = DidEntityForTesting + "#" + UhcPublicSingKeyIdForTesting

func TestCreateSignedDidDocument(t *testing.T) {
	// signerEntity := signature.GetEd25519Signer([]byte(issuerPrivKey), []byte(issuerPubKey))
	didDoc := createDidDocumentWithSigningKey(issuerPubKey)
	proofCreator := DidCreatorForTesting
	signedJWSDoc, err := SignDidDocument(issuerPrivKey,issuerPubKey, didDoc, proofCreator)
	require.NoError(t, err)
	require.NotEmpty(t, signedJWSDoc)
	fmt.Printf("verifyData %v \n", string(signedJWSDoc))
	fmt.Println(string(signedJWSDoc))

	var signedJWSMap map[string]interface{}
	err = json.Unmarshal(signedJWSDoc, &signedJWSMap)
	require.NoError(t, err)

	proofsIface, ok := signedJWSMap["proof"]
	require.True(t, ok)

	proofs, ok := proofsIface.([]interface{})
	require.True(t, ok)
	require.Len(t, proofs, 1)

	proofMap, ok := proofs[0].(map[string]interface{})
	require.True(t, ok)

	require.Equal(t, proofCreator, proofMap["creator"])
	require.Equal(t, "assertionMethod", proofMap["proofPurpose"])
	require.Equal(t, "Ed25519Signature2018", proofMap["type"])
	require.Contains(t, proofMap, "created")

	require.Contains(t, proofMap, "proofValue")
	// require.Contains(t, proofMap, "jws")
}

func createDidDocumentWithSigningKey(pubKey []byte) *didDocument.Doc {
	signingKey := didDocument.PublicKey{
		ID:         DidCreatorForTesting,
		Type:       Ed25519KeyType,
		Controller: DidEntityForTesting,
		Value:      pubKey,
	}
	createdTime := time.Now()

	didDoc := &didDocument.Doc{
		Context:   []string{DidContext, SecurityContext},
		ID:        DidEntityForTesting,
		PublicKey: []didDocument.PublicKey{signingKey},
		Created:   &createdTime,
	}
	return didDoc
}

func TestDocumentSigner_Sign1(t *testing.T) {
	proofCreator := DidCreatorForTesting
	signerEntity := signature.GetEd25519Signer([]byte(issuerPrivKey), []byte(issuerPubKey))
	signSuite := ed25519signature2018.New(suite.WithSigner(signerEntity))
	docSigner := documentSigner.New(signSuite)

	context := &documentSigner.Context{
		Creator:       proofCreator,
		SignatureType: ed25519signature2018.SignatureType,
		// SignatureRepresentation: proof.SignatureJWS,
	}

	// signedDoc, err := docSigner.Sign(context, []byte(validDoc))	// invalid JSON-LD context
	// signedDoc, err := createSignedDidDocument(context, []byte(validDoc))	// invalid JSON-LD context
	// require.NoError(t, err)
	// require.NotNil(t, signedDoc)

	signedDoc2 := ed25519.Sign(issuerPrivKey, []byte(validDoc))
	require.NotNil(t, signedDoc2)

	context.SignatureRepresentation = proof.SignatureJWS
	signedJWSDoc, err := docSigner.Sign(context, []byte(validDoc))
	require.NoError(t, err)
	require.NotNil(t, signedJWSDoc)
}

const (
	didKey         = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	didKeyID       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
	agreementKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" //nolint:lll

	pubKeyBase58       = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	keyAgreementBase58 = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
)

func TestBuild(t *testing.T) {
// t.Run("build with default key type", func(t *testing.T) {
	v := key.New()

	pubKey := &vdriapi.PubKey{
		Type:  Ed25519KeyType,
		// Value: base58.Decode(pubKeyBase58),
	}

	doc, err := v.Build(pubKey)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// assertDoc(t, doc)
}

/*
func assertDoc(t *testing.T, doc *didDocument.Doc) {
	// validate @context
	require.Equal(t, didDocument.schemaV1, doc.Context[0])

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := &did.VerificationMethod{
		ID:         didKeyID,
		Type:       ed25519VerificationKey2018,
		Controller: didKey,
		Value:      base58.Decode(pubKeyBase58),
	}

	expectedKeyAgreement := &did.VerificationMethod{
		ID:         agreementKeyID,
		Type:       x25519KeyAgreementKey2019,
		Controller: didKey,
		Value:      base58.Decode(keyAgreementBase58),
	}

	// validate publicKey
	assertPubKey(t, expectedPubKey, &doc.VerificationMethod[0])

	// validate assertionMethod
	assertPubKey(t, expectedPubKey, &doc.AssertionMethod[0].VerificationMethod)

	// validate authentication
	assertPubKey(t, expectedPubKey, &doc.Authentication[0].VerificationMethod)

	// validate capabilityDelegation
	assertPubKey(t, expectedPubKey, &doc.CapabilityDelegation[0].VerificationMethod)

	// validate capabilityInvocation
	assertPubKey(t, expectedPubKey, &doc.CapabilityInvocation[0].VerificationMethod)

	// validate keyAgreement
	assertPubKey(t, expectedKeyAgreement, &doc.KeyAgreement[0].VerificationMethod)
}


func assertPubKey(t *testing.T, expectedPubKey, actualPubKey *did.VerificationMethod) {
	require.NotNil(t, actualPubKey)
	require.Equal(t, expectedPubKey.ID, actualPubKey.ID)
	require.Equal(t, expectedPubKey.Type, actualPubKey.Type)
	require.Equal(t, expectedPubKey.Controller, actualPubKey.Controller)
	require.Equal(t, expectedPubKey.Value, actualPubKey.Value)
}

 */
