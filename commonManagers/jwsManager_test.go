package commonManagers

import (
	"crypto/sha512"
	"encoding/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestJWS(t *testing.T) {

}

/*
	Package ed25519signature2018 implements the Ed25519Signature2018 signature suite for the Linked Data Signatures [LD-SIGNATURES] specification.
	It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION] to transform the input document into its canonical form.
	It uses SHA-256 [RFC6234] as the message digest algorithm and Ed25519 [ED25519] as the signature algorithm.
	https://godoc.org/github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018
*/

func TestCreateVerifyData(t *testing.T) {
	// publicSignKey, secretSignKey, err := ed25519.GenerateKey(nil)
	// ed25519.Sign()
	// ed25519.Verify()

	signSuite := ed25519signature2018.New()
	/*
	ed25519signature2018.Suite.CompactProof()
	ed25519signature2018.Suite.GetCanonicalDocument()
	ed25519signature2018.Suite.GetDigest()
	ed25519signature2018.Suite.Sign()
	ed25519signature2018.Suite.Verify()
	ed25519signature2018.Suite.Accept()
	*/

	// It creates the detached JWT Header
	jwtHeader := proof.CreateDetachedJWTHeader(&proof.Proof{
		Type: ed25519signature2018.SignatureType,
	})
	jwtHeaderMap := GetJwtHeaderMap(jwtHeader)
	require.Equal(t, "EdDSA", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])

	// It creates the proof
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	// creator will contain didID#keyID
	/*
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}
	keyHandler, err := keyManager.Get(idSplit[1])
	*/
	p := &proof.Proof{
		Type:    ed25519signature2018.SignatureType,	// same as jwtHeader.Type
		Created: util.NewTime(created),
		Creator: "didID#keyID",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	p.SignatureRepresentation = proof.SignatureJWS
	p.JWS = "jws header.."
	// normalizedDoc, err := proof.CreateVerifyData(&mockSignatureSuite{}, doc, p)
	normalizedDoc, err := proof.CreateVerifyData(signSuite, doc, p)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

}

type mockSignatureSuite struct {
	compactProof bool
}

// GetCanonicalDocument will return normalized/canonical version of the document.
func (s *mockSignatureSuite) GetCanonicalDocument(doc map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	return jsonld.Default().GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *mockSignatureSuite) GetDigest(doc []byte) []byte {
	digest := sha512.Sum512(doc)
	return digest[:]
}

func (s *mockSignatureSuite) CompactProof() bool {
	return s.compactProof
}

//nolint:lll
const validDoc = `{
  "@context": ["https://w3id.org/did/v1"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "created": "2002-10-10T17:00:00Z"
}`

// from https://json-ld.org/test-suite/reports/#test_a5ebfe589bd62d1029790695808f8ff9
const test1 = `{
  "@id": "http://greggkellogg.net/foaf#me",
  "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg"
}`

const test1Result = `<http://greggkellogg.net/foaf#me> <http://xmlns.com/foaf/0.1/name> "Gregg Kellogg" .
`
