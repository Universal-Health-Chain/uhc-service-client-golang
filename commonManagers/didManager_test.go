package commonManagers

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const (
	didContext      		= "https://www.w3.org/ns/did/v1"
	securityContext        	= "https://w3id.org/security/v2"
	securityContextJWK2020 	= "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
)

const (
	jwtPartsNumber   = 3
	jwtHeaderPart    = 0
	jwtSignaturePart = 2
)

const did = "did:method:abc"
const creator = did + "#key-1"
const keyType = "Ed25519VerificationKey2018"
const signatureType = "Ed25519Signature2018"

func TestCreateSignedDidDocument(t *testing.T) {
	// signerEntity := signature.GetEd25519Signer([]byte(issuerPrivKey), []byte(issuerPubKey))
	signedDoc,err := createSignedDidDocument(issuerPrivKey,issuerPubKey)
	require.NoError(t, err)
	require.NotEmpty(t, signedDoc)
	fmt.Printf("verifyData %v \n", string(signedDoc))
	fmt.Println(string(signedDoc))
}

func createDidDocumentWithSigningKey(pubKey []byte) *didDocument.Doc {
	signingKey := didDocument.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: did,
		Value:      pubKey,
	}
	createdTime := time.Now()

	didDoc := &didDocument.Doc{
		Context:   []string{didContext, securityContext},
		ID:        did,
		PublicKey: []didDocument.PublicKey{signingKey},
		Created:   &createdTime,
	}
	return didDoc
}

func createSignedDidDocument(privKey, pubKey []byte) ([]byte, error) {
	didDoc := createDidDocumentWithSigningKey(pubKey)
	jsonDoc, err := didDoc.JSONBytes()
	// doc, err := didDocument.ParseDocument([]byte(validDoc))
	// jsonDoc2, err := doc.JSONBytes()
	if err != nil { return nil, err }

	signerEntity := signature.GetEd25519Signer(privKey, pubKey)
	signSuite := ed25519signature2018.New(suite.WithSigner(signerEntity))
	docSigner := documentSigner.New(signSuite)

	context := &documentSigner.Context{
		Creator: creator,
		SignatureType: signatureType,
	}

	signedDoc, err := docSigner.Sign(context, jsonDoc, jsonld.WithDocumentLoader(didDocument.CachingJSONLDLoader()))
	return signedDoc, err
}

func TestDocumentSigner_Sign(t *testing.T) {
	signerEntity := signature.GetEd25519Signer([]byte(issuerPrivKey), []byte(issuerPubKey))
	signSuite := ed25519signature2018.New(suite.WithSigner(signerEntity))
	docSigner := documentSigner.New(signSuite)

	context := &documentSigner.Context{
		Creator:       "creator",
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

	require.Equal(t, "creator", proofMap["creator"])
	require.Equal(t, "assertionMethod", proofMap["proofPurpose"])
	require.Equal(t, "Ed25519Signature2018", proofMap["type"])
	require.Contains(t, proofMap, "created")
	require.Contains(t, proofMap, "jws")
}
