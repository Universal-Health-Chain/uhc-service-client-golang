package commonManagers


import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/piprate/json-gold/ld"
	"io"
	"strings"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
)
const jsonldContext = "@context"
const (
	// jsonldType is key for proof type.
	jsonldType = "type"
	// jsonldCreator is key for creator.
	jsonldCreator = "creator"
	// jsonldCreated is key for time proof created.
	jsonldCreated = "created"
	// jsonldDomain is key for domain name.
	jsonldDomain = "domain"
	// jsonldNonce is key for nonce.
	jsonldNonce = "nonce"
	// jsonldProofValue is key for proof value.
	jsonldProofValue = "proofValue"
	// jsonldProofPurpose is a purpose of proof.
	jsonldProofPurpose = "proofPurpose"
	// jsonldJWSProof is key for JWS proof.
	jsonldJWS = "jws"
	// jsonldVerificationMethod is a key for verification method.
	jsonldVerificationMethod = "verificationMethod"
	// jsonldChallenge is a key for challenge.
	jsonldChallenge = "challenge"
	// jsonldCapabilityChain is a key for capabilityChain.
	jsonldCapabilityChain = "capabilityChain"
)

const (
	jwtPartsNumber   = 3
	jwtHeaderPart    = 0
	jwtSignaturePart = 2
)

const (
	proofID excludedKey = iota + 1
	proofValue
	jws
	nonce
)

// excludedKey defines keys that are excluded for proof options.
type excludedKey uint

//nolint:gochecknoglobals
var (
	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
	excludedKeys    = [...]excludedKey{proofID, proofValue, jws, nonce}
)

// processorOpts holds options for canonicalization of JSON LD docs.
type processorOpts struct {
	removeInvalidRDF    bool
	validateRDF         bool
	documentLoader      ld.DocumentLoader
	externalContexts    []string
	documentLoaderCache map[string]interface{}
}

// ProcessorOpts are the options for JSON LD operations on docs (like canonicalization or compacting).
type ProcessorOpts func(opts *processorOpts)

// CreateDetachedJWTHeader creates detached JWT header.
func CreateDetachedJWTHeader(p *proof.Proof) string {
	var jwsAlg string

	// TODO this is a hacky workaround, to be improved
	//  (https://github.com/hyperledger/aries-framework-go/issues/1589)
	switch p.Type {
	case "EcdsaSecp256k1Signature2019":
		jwsAlg = "ES256K"
	case "Ed25519Signature2018":
		jwsAlg = "EdDSA"
	default:
		jwsAlg = p.Type
	}

	jwtHeaderMap := map[string]interface{}{
		"alg":  jwsAlg,
		"b64":  false,
		"crit": []string{"b64"},
	}

	jwtHeaderBytes, err := json.Marshal(jwtHeaderMap)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(jwtHeaderBytes)
}

// GetJWTSignature returns signature part of JWT.
func GetJWTSignature(jwt string) ([]byte, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber || jwtParts[jwtSignaturePart] == "" {
		return nil, errors.New("invalid JWT")
	}

	return base64.RawURLEncoding.DecodeString(jwtParts[jwtSignaturePart])
}

// signatureSuite encapsulates signature suite methods required for normalizing document.
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool
}

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyData(suite signatureSuite, jsonldDoc map[string]interface{}, proof *proof.Proof, opts ...jsonld.ProcessorOpts) ([]byte, error) {
	return createVerifyJWS(suite, jsonldDoc, proof, opts...)
}

// createVerifyJWS creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func createVerifyJWS(suite signatureSuite, jsonldDoc map[string]interface{}, p *proof.Proof,
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	proofOptions := p.JSONLdObject()

	canonicalProofOptions, err := prepareJWSProof(suite, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := suite.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(suite, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := suite.GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)

	jwtHeader, err := getJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

func getJWTHeader(jwt string) (string, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber {
		return "", errors.New("invalid JWT")
	}

	return jwtParts[jwtHeaderPart], nil
}

func prepareJWSProof(suite signatureSuite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions[jsonldContext] = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		proofOptionsCopy[key] = value
	}

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofValue)

	return suite.GetCanonicalDocument(proofOptionsCopy, append(opts, WithDocumentLoaderCache(models.JsonldCache))...)
}

func prepareDocumentForJWS(suite signatureSuite, jsonldObject map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	doc := proof.GetCopyWithoutProof(jsonldObject)

	if suite.CompactProof() {
		opts = append(opts, WithDocumentLoaderCache(models.JsonldCache))

		docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
		if err != nil {
			return nil, err
		}

		doc = docCompacted
	}

	// build canonical document
	return suite.GetCanonicalDocument(doc, opts...)
}

// WithDocumentLoaderCache option is for passing cached contexts to be used by JSON-LD context document loader.
// Supported value types: map[string]interface{}, string, []byte, io.Reader.
func WithDocumentLoaderCache(cache map[string]interface{}) jsonld.ProcessorOpts {
	return func(opts *processorOpts) {
		if opts.documentLoaderCache == nil {
			opts.documentLoaderCache = make(map[string]interface{})
		}

		for k, v := range cache {
			if cacheValue := getDocumentCacheValue(v); cacheValue != nil {
				opts.documentLoaderCache[k] = cacheValue
			}
		}
	}
}

func getDocumentCacheValue(v interface{}) interface{} {
	switch cv := v.(type) {
	case map[string]interface{}:
		return cv

	case string:
		var m map[string]interface{}

		if err := json.Unmarshal([]byte(cv), &m); err == nil {
			return m
		}

	case []byte:
		var m map[string]interface{}

		if err := json.Unmarshal(cv, &m); err == nil {
			return m
		}

	case io.Reader:
		if reader, err := ld.DocumentFromReader(cv); err == nil {
			return reader
		}
	}

	return nil
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...jsonld.ProcessorOpts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return jsonld.Default().Compact(docMap, contextMap, opts...)
}

func prepareCanonicalDocument(suite signatureSuite, jsonldObject map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	docCopy := proof.GetCopyWithoutProof(jsonldObject)

	// build canonical document
	return suite.GetCanonicalDocument(docCopy, opts...)
}

func prepareCanonicalProofOptions(suite signatureSuite, proofOptions map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	value, ok := proofOptions[jsonldCreated]
	if !ok || value == nil {
		return nil, errors.New("created is missing")
	}

	// copy from the original proof options map without specific keys
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		if excludedKeyFromString(key) == 0 {
			proofOptionsCopy[key] = value
		}
	}

	if suite.CompactProof() {
		opts = append(opts, WithDocumentLoaderCache(models.JsonldCache))

		docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy, opts...)
		if err != nil {
			return nil, err
		}

		proofOptionsCopy = docCompacted
	}

	// build canonical proof options
	return suite.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func excludedKeyFromString(s string) excludedKey {
	for _, ek := range excludedKeys {
		if ek.String() == s {
			return ek
		}
	}

	return 0
}

func (ek excludedKey) String() string {
	return excludedKeysStr[ek-1]
}