package commonManagers

import (
	"encoding/json"
	"fmt"
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	signVerifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	// "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/key"
	"github.com/stretchr/testify/require"
	"testing"
)

const DefaultProofPurpose = "assertionMethod"

func Test_CreateDefaultDID(t *testing.T) {
	didDoc, err := CreateDefaultDID(Ed25519SignKeyPairForTesting, X25519EncryptKeyPairForTesting)
	require.NoError(t, err)
	fmt.Printf("default did with both sign and encryption public keys = %v \n", didDoc)
}

func Test_CreateSignedDidDocument(t *testing.T) {
	// signerEntity := signature.GetEd25519Signer([]byte(Ed25519PrivateKeyBytesForTesting), []byte(Ed25519PublicKeyBytesForTesting))
	// didDoc := createDidDocumentWithSigningKeyForTesting(Ed25519PublicKeyBytesForTesting)
	didDoc, err := CreateDefaultDID(Ed25519SignKeyPairForTesting, X25519EncryptKeyPairForTesting)
	require.NoError(t, err)

	proofCreator := UserVerifyPublicKeyDID
	signedDidDoc, err := SignDidDocument(Ed25519PrivateKeyBytesForTesting, Ed25519PublicKeyBytesForTesting, didDoc, proofCreator)
	require.NoError(t, err)
	require.NotEmpty(t, signedDidDoc)
	fmt.Printf("verifyData %v \n", string(signedDidDoc))
	// fmt.Println(string(signedDidDoc))

	var signedJWSMap map[string]interface{}
	err = json.Unmarshal(signedDidDoc, &signedJWSMap)
	require.NoError(t, err)

	proofsIface, ok := signedJWSMap["proof"]
	require.True(t, ok)

	proofs, ok := proofsIface.([]interface{})
	require.True(t, ok)
	require.Len(t, proofs, 1)

	proofMap, ok := proofs[0].(map[string]interface{})
	require.True(t, ok)

	require.Equal(t, proofCreator, proofMap["creator"])
	require.Equal(t, DefaultProofPurpose, proofMap["proofPurpose"])
	require.Equal(t, Ed25519SignatureType, proofMap["type"])	// Signature, but not Ed25519KeyType of type "Ed25519VerificationKey2018"
	require.Contains(t, proofMap, "created")

	require.Contains(t, proofMap, "proofValue")
	// require.Contains(t, proofMap, "jws")
}

func Test_ValidateDidSignedProof(t *testing.T) {
	// didDoc := createDidDocumentWithSigningKeyForTesting(Ed25519PublicKeyBytesForTesting)
	didDoc, err := CreateDefaultDID(Ed25519SignKeyPairForTesting, X25519EncryptKeyPairForTesting)
	require.NoError(t, err)

	proofCreator := UserVerifyPublicKeyDID
	signedDoc, err := SignDidDocument(Ed25519PrivateKeyBytesForTesting, Ed25519PublicKeyBytesForTesting, didDoc, proofCreator)
	// signedDoc2 := ed25519.Sign(Ed25519PrivateKeyBytesForTesting, []byte(validDoc))
	require.Nil(t, err)
	println("signedDoc = ", string(signedDoc))

	parsedDoc, err := didDocument.ParseDocument(signedDoc)
	require.Nil(t, err)
	require.NotNil(t, parsedDoc)

	// verify proof.Value of a DID document with did.VerifyProof()
	verifierSignatureSuites := []signVerifier.SignatureSuite{
		ed25519signature2018.New(
			suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()),	// keyType: "OKP", curve: "Ed25519", algorithm: "EdDSA"
			suite.WithCompactProof()),
		// other suites...
		// ecdsasecp256k1signature2019.New(suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier())),
	}

	err = parsedDoc.VerifyProof(verifierSignatureSuites)
	require.Nil(t, err)
}

func Test_CreateDidKeyDocumentNotUHC(t *testing.T) {
	v := key.New()

	pubKey := &vdriapi.PubKey{
		Type:  Ed25519KeyType,
		Value: Ed25519PublicKeyBytesForTesting,
	}

	doc, err := v.Build(pubKey)
	require.NoError(t, err)
	require.NotNil(t, doc)
	fmt.Printf("DID document from key = %v \n", doc)
}


// DID Document capabilites, Verification method and KeyAgreement: https://whitepaper.fission.codes/identity/did-doc
const DidDocSignedForTesting = `
{
  "@context":[
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/v2"
  ],
  "authentication":[
    "did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e#aaab749d-ccfc-44a7-9bbc-b7d22999ff5f"
  ],
  "created":"2020-01-01T20:21:22Z",
  "id":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e",
  "keyAgreement":[
    "did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e#2412b88c-6a70-494f-8cd1-f43acc4b852c"
  ],
  "proof":[
    {
      "created":"2020-12-30T18:33:17.624003+01:00",
      "creator":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e#aaab749d-ccfc-44a7-9bbc-b7d22999ff5f",
      "proofPurpose":"assertionMethod",
      "proofValue":"ZWJLR2y3VvuErvF0Upvd4PPX7reit7cDK_8Nr7PHWcoihxHiqvDeUQBNTJZrQCTwMvM0n-ZfBMU_9F_G9YMTAw",
      "type":"Ed25519Signature2018"
    }
  ],
  "publicKey":[
    {
      "controller":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e",
      "id":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e#aaab749d-ccfc-44a7-9bbc-b7d22999ff5f",
      "publicKeyBase58":"GmyWNNyGhRzhoKnE8yoJn12pDpoABjhn1PxqAroVzD94",
      "type":"Ed25519VerificationKey2018"
    },
    {
      "controller":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e",
      "id":"did:v1:uuid:5d96ea7b-ed86-4f73-b181-c32c0bd9a17e#2412b88c-6a70-494f-8cd1-f43acc4b852c",
      "publicKeyBase58":"8J42xZoLrV3VtLTEgkJeg7FShBUBHeT1NWntLrXofCdN",
      "type":"X25519KeyAgreementKey2019"
    }
  ]
}
`