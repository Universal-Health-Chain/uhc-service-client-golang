package commonManagers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"net/http"
	"strings"
	"time"

	jcsProof "github.com/Universal-Health-Chain/JcsEd25519Signature2020/signature-suite-impls/golang/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	signVerifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	josejwt "github.com/square/go-jose/v3/jwt"

	"testing"
)


var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)

	nonce      = "0948bb75-60c2-4a92-ad50-01ccee169ae0"
	creatorKey = UserVerifyPublicKeyDID

	testJSON      = `{"some":"one","test":"two","structure":"three"}`
	differentJSON = `{"some":"one","test":"two","structure":"banana"}`
)

func Test_GenericJsonSignWithJCS2020(t *testing.T) {
	sampleInput := `{"foo": "bar"}`
	signedDocBytes, err := SignWithJcs2020Proof(sampleInput, Ed25519SignKeyPairForTesting)
	assert.NoError(t, err)

	var signedDoc GenericJsonProvableWithJCS
	assert.NoError(t, json.Unmarshal(signedDocBytes, &signedDoc))

	signPublicKeyBytes, _ := Base64StringToBytes(Ed25519SignKeyPairForTesting.PublicKeyBase64)
	assert.NoError(t, jcsProof.VerifyEd25519Proof(&signedDoc, signPublicKeyBytes))
}

func Test_GenerateProofJCS2020(t *testing.T) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(testJSON), &data)
	assert.NoError(t, err)

	provable := GenericJsonProvableWithJCS{Data: data}

	proofUnderTest, err := jcsProof.CreateEd25519Proof(&provable, issuerPrivKey, creatorKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, proofUnderTest.Nonce, nonce)
	assert.Equal(t, proofUnderTest.VerificationMethod, creatorKey)

	provable.Proof = *proofUnderTest
	assert.NoError(t, jcsProof.VerifyEd25519Proof(&provable, issuerPubKey))
}

func Test_ValidateProofJCS2020(t *testing.T) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(testJSON), &data)
	assert.NoError(t, err)

	provable := GenericJsonProvableWithJCS{Data: data}

	proofUnderTest, err := jcsProof.CreateEd25519Proof(&provable, issuerPrivKey, creatorKey, nonce)
	assert.NoError(t, err)

	provable.Proof = *proofUnderTest
	assert.NoError(t, jcsProof.VerifyEd25519Proof(&provable, issuerPubKey))
	assert.NoError(t, err)

	var differentData map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(differentJSON), &differentData))
	differentProvable := GenericJsonProvableWithJCS{Data: differentData}

	assert.Error(t, jcsProof.VerifyEd25519Proof(&differentProvable, issuerPubKey))
}


// Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE): CFRG Elliptic Curve ECDH and Signatures - RFC8037
// Edwards-curve Digital Signature Algorithm (EdDSA) for signing data using "JSON Web Signature (JWS)" [RFC7515]
// "crv" EdDSA Variant value is Ed25519: https://tools.ietf.org/html/rfc8037

func Test_SignWithAriesProofJWS(t *testing.T) {
	jsonSigned, err := SignWithAriesProof(Ed25519SignKeyPairForTesting, DigestToSignForTesting, true, "test") // validDoc)
	println("jsonSigned = ", string(jsonSigned))

	var signedJWSMap map[string]interface{}
	err = json.Unmarshal(jsonSigned, &signedJWSMap)
	require.NoError(t, err)

	proofsIface, ok := signedJWSMap["proof"]
	require.True(t, ok)

	proofs, ok := proofsIface.([]interface{})
	require.True(t, ok)
	require.Len(t, proofs, 1)

	proofMap, ok := proofs[0].(map[string]interface{})
	require.True(t, ok)

	require.Equal(t, UserVerifyPublicKeyDID, proofMap["creator"])
	require.Equal(t, "test", proofMap["proofPurpose"])
	require.Equal(t, Ed25519SignatureType, proofMap["type"])
	require.Contains(t, proofMap, "created")
	require.Contains(t, proofMap, "jws")
}

// JWS Detached is a variation of JWS that allows to sign content without its modification (json, body or HTTP request / response)
// Validation of data with JWS Detached is simple too:
// a) Get the HTTP header “x-jws signature” (if HTTP message)
// b) Get BASE64URL of data or HTTP body (remove first "proof" if has a detached proof
// c) Put the generated BASE64URL string b) into the Payload section of the JWS to validate
// d) Validate JWS

func xTest_VerifyProofValue(t *testing.T){
	signerPublicKeyForVerification := &signVerifier.PublicKey{
		Type:  Ed25519KeyType,	//kms.ED25519,
		Value: Ed25519PublicKeyBytesForTesting,
		// JWK is created?
	}
	fmt.Printf("signerPublicKeyForVerification.JWK = %v \n", signerPublicKeyForVerification.JWK)

	// First testing a single signature of text
	signatureBytes := ed25519.Sign(Ed25519PrivateKeyBytesForTesting, []byte("data for testing"))
	// This works
	err := jwt.VerifyEdDSA(signerPublicKeyForVerification, []byte("data for testing"), signatureBytes)
	require.Nil(t, err)

	// Serialize the encrypted object using the full serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	// serialized := object.FullSerialize()


	// Now it signs a JSON with a JWS in the 'proof' object
	jsonSignedWithProofBytes, err := SignWithAriesProof(Ed25519SignKeyPairForTesting, "data for testing", true,"test")
	require.Nil(t, err)
	println("signedDoc = ", string(jsonSignedWithProofBytes))

	var jsonSignedParsed map[string]interface{}
	err = json.Unmarshal(jsonSignedWithProofBytes, &jsonSignedParsed)
	require.NoError(t, err)

	// verify proof.Value of a DID document with did.VerifyProof()
	/*
		verifierSignatureSuites := []signVerifier.SignatureSuite{
			ed25519signature2018.New(
				suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()),	// keyType: "OKP", curve: "Ed25519", algorithm: "EdDSA"
				suite.WithCompactProof()),
			// other suites...
			// ecdsasecp256k1signature2019.New(suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier())),
		}
	*/

	// VerifyProof (adapted from didDocumentManager_test.Test_ValidateDidSignedProof)
	/*
		signerPublicKey := &signVerifier.PublicKey{
			Type:  signerPublicKeyForVerification.Type,
			Value: signerPublicKeyForVerification.Value,
			JWK: signerPublicKeyForVerification.JWK,
		}
	*/

	var signedDigest models.DigestSigned
	err = json.Unmarshal(jsonSignedWithProofBytes, &signedDigest)
	require.NoError(t, err)

	jwsString := signedDigest.Proof[0].JWS
	println("jws = ", jwsString)

	splittedJWS := strings.Split(jwsString, ".")
	jwtSignature := splittedJWS[JwtSignaturePart]
	fmt.Printf("jwtSignature = %v \n", jwtSignature)

	// Now it tries to do verify from the signed document, not from the original document
	delete(jsonSignedParsed, "proof")
	// TODO: canonize the jsonSignedParsed
	docWithoutProofValue, err := json.Marshal(jsonSignedParsed)
	require.NoError(t, err)

	var jsonWithoutProofParsed map[string]interface{}
	err = json.Unmarshal(docWithoutProofValue, &jsonWithoutProofParsed)
	require.NoError(t, err)
	fmt.Printf("jsonWithoutProofParsed = %v \n", jsonWithoutProofParsed)

	jwtPayload := base64.RawURLEncoding.EncodeToString(docWithoutProofValue)
	fmt.Printf("jwtPayload = %v \n", jwtPayload)
	jwtHeader := splittedJWS[JwtHeaderPart]
	fmt.Printf("jwtHeader = %v \n", jwtHeader)
	jwsToValidate := jwtHeader + "." + jwtPayload + "." + jwtSignature
	fmt.Printf("jwsToValidate = %v \n", jwsToValidate)

	// It tries to verify the signature using the original document, not the signed document
	signatureBytes = []byte(jwtSignature)
	// suiteVerifier := ed25519signature2018.NewPublicKeyVerifier()
	// signatureSuite := ed25519signature2018.New(suite.WithVerifier(suiteVerifier))
	verifier := signVerifier.Ed25519SignatureVerifier{}
	err = verifier.Verify(signerPublicKeyForVerification, []byte("data for testing"), signatureBytes)
	require.NoError(t, err)	// invalid signature

	err = jwt.VerifyEdDSA(signerPublicKeyForVerification, []byte("data for testing"), signatureBytes)
	require.Nil(t, err)	// "signature doesn't match

	// signatureSuite.Verifier.Verify(signerPublicKey, )
	/*
		v, err := signVerifier.New( signerPublicKeyForVerification, verifierSignatureSuites...)
		defaultDocumentLoaderOpt := []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(CachingJSONLDLoader())}
		err = v.Verify(jsonSignedWithProofBytes, append(defaultDocumentLoaderOpt)...)
		require.Nil(t, err)
	*/

	err = jwt.VerifyEdDSA(signerPublicKeyForVerification, docWithoutProofValue, signatureBytes)
	require.NoError(t, err)

	// jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])

	// jsonWebToken, err := josejwt.ParseSigned(signedDigest.Proof[0].JWS)
	// jwtVerifier := jwt.NewVerifier(GetKeyResolver(signerPublicKeyForVerification, nil))
	// _, err = jose.ParseJWS(jwsString, jwtVerifier)
	// var jsonSignature = &jose.JSONWebSignature{ProtectedHeaders: nil, UnprotectedHeaders: nil, Payload: nil}
	// jsonSignature, err = jose.ParseJWS(jwsString, jwtVerifier)
	// joseVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{Alg: "EdDSA", Verifier: jwtVerifier,})
	// jsonWebToken, err := jwt.Parse(signedDigest.Proof[0].JWS) //, jwt.WithSignatureVerifier(joseVerifier))

	// var parsedClaims map[string]interface{}
	// err = jsonWebToken.DecodeClaims(&parsedClaims)
	// jsonWebToken, err = jwt.Parse(jwsDetached, jwt.WithSignatureVerifier(jwtVerifier), jwt.WithJWTDetachedPayload(jwsPayload), )

	// claims := jwt.Claims{}
	// err = jwt.Claims(Ed25519PublicKeyBytesForTesting, claims)
	//validation, err := VerifyEd25519ViaGoJose(signedDigest.Proof[0].JWS, Ed25519PublicKeyBytesForTesting, claims)

	// other way...
	// suiteSignatureSuite := suite.InitSuiteOptions(&suite.SignatureSuite{}, suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()), suite.WithCompactProof())
	// pubKey := &signVerifier.PublicKey{Type: Ed25519KeyType, Value: Ed25519PublicKeyBytesForTesting}
}

/*
func Test_BuildJWS(t *testing.T) {
	signer := jose.Signer()
	claims := createClaimsForTesting()

	jwsString, err := BuildJWS(signer, claims)
	require.NoError(t, err)
	println("jws = ", jwsString)

	claimsBytes, err := json.Marshal(claims)
	require.NoError(t, err)

	joseJWS, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	require.NoError(t, err)

	jwsSerialized := jose.SerializeCompact(false)
}
*/

func createClaimsForTesting() *jwt.Claims{
	issued := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	expiry := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

	return &jwt.Claims{
		Issuer:    "iss",
		Subject:   "sub",
		Audience:  []string{"aud"},
		Expiry:    josejwt.NewNumericDate(expiry),
		NotBefore: josejwt.NewNumericDate(notBefore),
		IssuedAt:  josejwt.NewNumericDate(issued),
		ID:        "id",
	}
}

// CachingJSONLDLoader creates JSON-LD CachingDocumentLoader with preloaded base JSON-LD DID and security contexts.
func CachingJSONLDLoader() ld.DocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	cacheContext := func(source, url string) {
		reader, _ := ld.DocumentFromReader(strings.NewReader(source)) //nolint:errcheck
		loader.AddDocument(url, reader)
	}
	// cacheContext(TestSchema, "https://test")
	cacheContext(DidV1Context, "https://w3id.org/did/v1")
	cacheContext(DidV1Context, "https://www.w3.org/ns/did/v1")
	cacheContext(SecurityV1Context, "https://w3id.org/security/v1")
	cacheContext(SecurityV2Context, "https://w3id.org/security/v2")

	return loader
}

//nolint:lll
const DigestToSignForTesting = `{
   "@context": ["https://www.w3.org/ns/did/v1"],
   "id": "",
   "type": "Digest",
   "digestValue": "3b13152c7af2e840af8ffe981cd782faa2b8332ef80087d487a6a664cca62317",
   "digestAlgorithm": "SHA3-256",
   "proofPurpose": "assertionMethod"
 }`

var DigestForTesting = models.DigestToSign{
	Type:            "Digest",
	Context:         []string{SecurityContext},
	DigestValue:     "3b13152c7af2e840af8ffe981cd782faa2b8332ef80087d487a6a664cca62317",
	DigestAlgorithm: "SHA3-256",
	ProofPurpose:    DefaultProofPurpose,
	// Capability:      "",
}

var DigestValueProofToSignForTesting = `
{
  "id": "https://w3id.org/security/v1#Ed25519Signature2018",
  "type": "Ed25519VerificationKey2018",
  "canonicalizationAlgorithm": "https://w3id.org/security#URDNA2015",
  "digestAlgorithm": "https://www.ietf.org/assignments/jwa-parameters#SHA256",
  "digestValue": "",
  "signatureAlgorithm": "https://w3id.org/security#ed25519"
}`


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

const DidV1Context = `
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "dc": "http://purl.org/dc/terms/",
    "schema": "http://schema.org/",
    "sec": "https://w3id.org/security#",
    "didv": "https://w3id.org/did#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "SchnorrSecp256k1Signature2019": "sec:SchnorrSecp256k1Signature2019",
    "SchnorrSecp256k1VerificationKey2019": "sec:SchnorrSecp256k1VerificationKey2019",
    "ServiceEndpointProxyService": "didv:ServiceEndpointProxyService",
    "allowedAction": "sec:allowedAction",
    "assertionMethod": {
      "@id": "sec:assertionMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "authentication": {
      "@id": "sec:authenticationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capability": {
      "@id": "sec:capability",
      "@type": "@id"
    },
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {
      "@id": "sec:capabilityChain",
      "@type": "@id",
      "@container": "@list"
    },
    "capabilityDelegation": {
      "@id": "sec:capabilityDelegationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityInvocation": {
      "@id": "sec:capabilityInvocationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityStatusList": {
      "@id": "sec:capabilityStatusList",
      "@type": "@id"
    },
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "caveat": {
      "@id": "sec:caveat",
      "@type": "@id",
      "@container": "@set"
    },
    "challenge": "sec:challenge",
    "controller": {
      "@id": "sec:controller",
      "@type": "@id"
    },
    "created": {
      "@id": "dc:created",
      "@type": "xsd:dateTime"
    },
    "creator": {
      "@id": "dc:creator",
      "@type": "@id"
    },
    "delegator": {
      "@id": "sec:delegator",
      "@type": "@id"
    },
    "domain": "sec:domain",
    "expirationDate": {
      "@id": "sec:expiration",
      "@type": "xsd:dateTime"
    },
    "invocationTarget": {
      "@id": "sec:invocationTarget",
      "@type": "@id"
    },
    "invoker": {
      "@id": "sec:invoker",
      "@type": "@id"
    },
    "jws": "sec:jws",
    "keyAgreement": {
      "@id": "sec:keyAgreementMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "nonce": "sec:nonce",
    "owner": {
      "@id": "sec:owner",
      "@type": "@id"
    },
    "proof": {
      "@id": "sec:proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "proofPurpose": {
      "@id": "sec:proofPurpose",
      "@type": "@vocab"
    },
    "proofValue": "sec:proofValue",
    "publicKey": {
      "@id": "sec:publicKey",
      "@type": "@id",
      "@container": "@set"
    },
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyJwk": {
      "@id": "sec:publicKeyJwk",
      "@type": "@json"
    },
    "revoked": {
      "@id": "sec:revoked",
      "@type": "xsd:dateTime"
    },
    "service": {
      "@id": "didv:service",
      "@type": "@id",
      "@container": "@set"
    },
    "serviceEndpoint": {
      "@id": "didv:serviceEndpoint",
      "@type": "@id"
    },
    "updated": {
      "@id": "dc:modified",
      "@type": "xsd:dateTime"
    },
    "verificationMethod": {
      "@id": "sec:verificationMethod",
      "@type": "@id"
    }
  }
}
`


