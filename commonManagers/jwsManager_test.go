package commonManagers

import (
	"encoding/json"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	signerDocument "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"testing"
)

var DigestForTesting = models.DigestToSign{
	Type:            "Digest",
	Context:         []string{SecurityContext},
	DigestValue:     "3b13152c7af2e840af8ffe981cd782faa2b8332ef80087d487a6a664cca62317",
	DigestAlgorithm: "SHA3-256",
	ProofPurpose:    DefaultProofPurpose,
	// Capability:      "",
}

func Test_SignDidWithProofJWS(t *testing.T) {
	// serializedJson := didDocument.
	signedJWSDoc, err := SignJsonWithProofJWS(SignKeyPairForTesting, validDoc, "test")	// validDoc)
	// println("signedJWSDoc = ", string(signedJWSDoc))

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

	require.Equal(t, UserSignPublicKeyDID, proofMap["creator"])
	require.Equal(t, "assertionMethod", proofMap["proofPurpose"])
	require.Equal(t, Ed25519SignatureType, proofMap["type"])
	require.Contains(t, proofMap, "CreatedTImeForTesting")
	require.Contains(t, proofMap, "jws")
}

/*
	Package ed25519signature2018 implements the Ed25519Signature2018 signature suite for the Linked Data Signatures [LD-SIGNATURES] specification.
	It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION] to transform the input document into its canonical form.
	It uses SHA-256 [RFC6234] as the message digest algorithm and Ed25519 [ED25519] as the signature algorithm.
	https://godoc.org/github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018
*/

func Test_Sign2(t *testing.T) {
	ed25519Signer := signature.GetEd25519Signer([]byte(Ed25519PrivateKeyBytesForTesting), []byte(Ed25519PublicKeyBytesForTesting))
	signSuite := ed25519signature2018.New(suite.WithSigner(ed25519Signer))

	now := time.Now()
	created := &now

	docSigner := signerDocument.New(signSuite)
	contextSigner := &signerDocument.Context{
		SignatureType:           Ed25519SignatureType,
		Creator:                 UserDIDForTesting,
		SignatureRepresentation: proof.SignatureJWS,
		Created:                 created, // &util.TimeWithTrailingZeroMsec{Time: *created},
		Domain:                  "",
		Nonce:                   nil,
		VerificationMethod:      "",
		Challenge:               "",
		Purpose:                 DefaultProofPurpose,
	}

	signedDoc, err := docSigner.Sign(contextSigner, []byte(digestToSign), jsonld.WithDocumentLoader(CachingJSONLDLoader()))	// it fails here
	// signedDoc, err := signSuite.Sign(canonicalDoc)
	require.NoError(t, err)

	var signedJson map[string]interface{}
	err = json.Unmarshal(signedDoc, &signedJson)
	require.NoError(t, err)

	println("signedDoc = ", string(signedDoc))
}

// CachingJSONLDLoader creates JSON-LD CachingDocumentLoader with preloaded base JSON-LD DID and security contexts.
func CachingJSONLDLoader() ld.DocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	cacheContext := func(source, url string) {
		reader, _ := ld.DocumentFromReader(strings.NewReader(source)) //nolint:errcheck
		loader.AddDocument(url, reader)
	}
	cacheContext(TestSchema, "https://test")
	cacheContext(SecurityV1Context, "https://w3id.org/security/v1")
	cacheContext(SecurityV2Context, "https://w3id.org/security/v2")

	return loader
}

//nolint:lll
const digestToSign = `{
  "@context": ["https://test", "https://w3id.org/security/v1"],
	"controller": "uuid"
}`

const validDoc = `{
  "@context": ["https://w3id.org/did/v1", "https://w3id.org/security/v2"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
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
  "CreatedTImeForTesting": "2002-10-10T17:00:00Z"
}`

// cached value from https://w3id.org/security/v2
const TestSchema = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "dc": "http://purl.org/dc/terms/",
    "schema": "http://schema.org/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "JsonWebKey2020": "sec:JsonWebKey2020",
    "JsonWebSignature2020": "sec:JsonWebSignature2020",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "SchnorrSecp256k1VerificationKey2019": "sec:SchnorrSecp256k1VerificationKey2019",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",
    "ServiceEndpointProxyService": "didv:ServiceEndpointProxyService",
    "controller": {
      "@id": "sec:controller",
      "@type": "@id"
    },
    "created": {
      "@id": "dc:created",
      "@type": "xsd:dateTime"
    }
  }
}
`

const SecurityV1Context = `
{
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyWif": "sec:publicKeyWif",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
}
`

const SecurityV2Context = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256r1Signature2019": "sec:EcdsaSecp256r1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2019": "sec:EcdsaSecp256r1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}
`

