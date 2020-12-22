package commonManagers

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

import (
	"encoding/base64"
	"encoding/json"
	"crypto/sha512"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/stretchr/testify/require"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"testing"
	"time"
)

//nolint:gochecknoglobals
var jsonldDidCache = WithDocumentLoaderCache(
	map[string]interface{}{
		"https://w3id.org/did/v1": models.DidDocSchema,
	})


func Test_getJWTHeader(t *testing.T) {
	jwtHeader, err := getJWTHeader("eyJ0eXAiOiJK..gFWFOEjXk")
	require.NoError(t, err)
	require.Equal(t, "eyJ0eXAiOiJK", jwtHeader)

	jwtHeader, err = getJWTHeader("invalid jwt")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, jwtHeader)
}

func Test_createVerifyJWS(t *testing.T) {
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	p := &proof.Proof{
		Type:         "Ed25519Signature2018",
		Created:      util.NewTime(created),
		JWS:          "eyJ0eXAiOiJK..gFWFOEjXk",
		ProofPurpose: "assertionMethod",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	// happy path - no proof compaction
	proofVerifyData, err := createVerifyJWS(&mockSignatureSuite{}, doc, p, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, proofVerifyData)

	// happy path - with proof compaction
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{compactProof: true}, doc, p, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, proofVerifyData)

	// artificial example - failure of doc canonization
	doc["type"] = 777
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p, jsonldDidCache)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid type value")
	require.Empty(t, proofVerifyData)

	// invalid JWT passed (we need to read a header from it to prepare verify data)
	doc["type"] = "Ed25519Signature2018"
	p.JWS = "invalid jws"
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p, jsonldDidCache)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JWT")
	require.Empty(t, proofVerifyData)
}

func TestCreateDetachedJWTHeader(t *testing.T) {
	getJwtHeaderMap := func(jwtHeaderB64 string) map[string]interface{} {
		jwtHeaderBytes, err := base64.RawURLEncoding.DecodeString(jwtHeaderB64)
		require.NoError(t, err)

		var jwtHeaderMap map[string]interface{}
		err = json.Unmarshal(jwtHeaderBytes, &jwtHeaderMap)
		require.NoError(t, err)

		return jwtHeaderMap
	}

	jwtHeader := CreateDetachedJWTHeader(&proof.Proof{
		Type: "Ed25519Signature2018",
	})
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap := getJwtHeaderMap(jwtHeader)
	require.Equal(t, "EdDSA", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])

	jwtHeader = CreateDetachedJWTHeader(&proof.Proof{
		Type: "EcdsaSecp256k1Signature2019",
	})
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap = getJwtHeaderMap(jwtHeader)
	require.Equal(t, "ES256K", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])

	jwtHeader = CreateDetachedJWTHeader(&proof.Proof{
		Type: "JsonWebSignature2020",
	})
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap = getJwtHeaderMap(jwtHeader)
	// TODO this should be improved (https://github.com/hyperledger/aries-framework-go/issues/1589)
	require.Equal(t, "JsonWebSignature2020", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])
}

func TestGetJWTSignature(t *testing.T) {
	jwtSignature := base64.RawURLEncoding.EncodeToString([]byte("test signature"))
	jws := "header.payload." + jwtSignature

	// happy path
	signature, err := GetJWTSignature(jws)
	require.NoError(t, err)
	require.Equal(t, []byte("test signature"), signature)

	// not JWS
	signature, err = GetJWTSignature("incorrect JWS structure")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, signature)

	// empty signature (unsecured JWT)
	signature, err = GetJWTSignature("header.payload.")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, signature)
}

// ---- data_test.go ----
func TestCreateVerifyHashAlgorithm(t *testing.T) {
	proofOptions := map[string]interface{}{
		"type":    "type",
		"creator": "key1",
		"created": "2018-03-15T00:00:00Z",
	}

	var doc map[string]interface{}
	err := json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	normalizedDoc, err := proof.CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// test error due to missing proof option
	delete(proofOptions, jsonldCreated)
	normalizedDoc, err = proof.CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions, jsonldDidCache)
	require.NotNil(t, err)
	require.Nil(t, normalizedDoc)
	require.Contains(t, err.Error(), "created is missing")
}

func TestPrepareCanonicalDocument(t *testing.T) {
	var doc map[string]interface{}
	err := json.Unmarshal([]byte(test1), &doc)
	require.NoError(t, err)

	normalizedDoc, err := prepareCanonicalDocument(&mockSignatureSuite{}, doc)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)
	require.Equal(t, test1Result, string(normalizedDoc))
}

func TestPrepareCanonicalProofOptions(t *testing.T) {
	proofOptions := map[string]interface{}{
		"@context": []interface{}{"https://w3id.org/did/v1"},
		"type":     "type",
		"creator":  "key1",
		"created":  "2018-03-15T00:00:00Z",
		"domain":   "abc.com",
		"nonce":    "nonce",
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(&mockSignatureSuite{}, proofOptions, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, canonicalProofOptions)

	// test missing created
	delete(proofOptions, jsonldCreated)
	canonicalProofOptions, err = prepareCanonicalProofOptions(&mockSignatureSuite{}, proofOptions, jsonldDidCache)
	require.NotNil(t, err)
	require.Nil(t, canonicalProofOptions)
	require.Contains(t, err.Error(), "created is missing")
}

func TestCreateVerifyData(t *testing.T) {
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	p := &proof.Proof{
		Type:    "type",
		Created: util.NewTime(created),
		Creator: "key1",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	p.SignatureRepresentation = proof.SignatureProofValue
	normalizedDoc, err := CreateVerifyData(&mockSignatureSuite{}, doc, p, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	p.SignatureRepresentation = proof.SignatureProofValue
	normalizedDoc, err = CreateVerifyData(&mockSignatureSuite{compactProof: true}, doc, p, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	p.SignatureRepresentation = proof.SignatureJWS
	p.JWS = "jws header.."
	normalizedDoc, err = CreateVerifyData(&mockSignatureSuite{}, doc, p, jsonldDidCache)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// unsupported signature representation
	p.SignatureRepresentation = proof.SignatureRepresentation(-1)
	signature, err := CreateVerifyData(&mockSignatureSuite{}, doc, p, jsonldDidCache)

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signature representation")
	require.Nil(t, signature)
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
  "verificationMethod": [
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
