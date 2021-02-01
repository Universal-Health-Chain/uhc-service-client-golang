/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"errors"
	didDocument "github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/did"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/jsonld"
	documentSigner "github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/signer"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/suite"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/util/signature"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"time"
)

const (
	DIDMethod 				= "did:v1:uuid:"
	CreatorParts			= 2
	X25519KeyType 			= "X25519KeyAgreementKey2019"
	Ed25519KeyType 			= "Ed25519VerificationKey2018"
	Ed25519SignatureType 	= "Ed25519Signature2018"
	DidSchemaV1				= "https://w3id.org/did/v1"
	DidContext             	= "https://www.w3.org/ns/did/v1"
	SecurityContext        	= "https://w3id.org/security/v2"
	X25519pub = 0xec // Curve25519 public key in multicodec table https://github.com/multiformats/multicodec/blob/master/table.csv.
)

// GetCanonicalDocument will return normalized/canonical version of the document.
func GetCanonicalDocument(doc map[string]interface{}, opts ...jsonld.ProcessorOpts) ([]byte, error) {
	return jsonld.Default().GetCanonicalDocument(doc, opts...)
}

func SignDidDocument(privKey, pubKey []byte, doc *didDocument.Doc, proofCreator string) ([]byte, error) {
	jsonDoc, err := doc.JSONBytes()
	if err != nil { return nil, err }

	signerEntity := signature.GetEd25519Signer(privKey, pubKey)
	signSuite := ed25519signature2018.New(suite.WithSigner(signerEntity))
	docSigner := documentSigner.New(signSuite)

	context := &documentSigner.Context{
		Creator:       proofCreator,	// "did:v1:uuid:" + EntityDidBlockchainUuid + "#" + UhcPublicSingKeyId
		SignatureType: Ed25519SignatureType,
	}

	signedDoc, err := docSigner.Sign(context, jsonDoc, jsonld.WithDocumentLoader(didDocument.CachingJSONLDLoader()))
	return signedDoc, err
}

// The ID of the DID Document is the KeyPair.PublicKeyInfo.ControllerDID of both sign and encryption key pairs
func CreateDefaultDID(signKeyPair models.Key, encryptKeyPair models.Key) (*didDocument.Doc, error) {
	// TODO: check if KeyPair have all the required fields

	if signKeyPair.ControllerDID == "" || signKeyPair.ControllerDID != encryptKeyPair.ControllerDID {
		return nil, errors.New("KeyPair's ControllerDID error")
	}

	// It converts base64 public keys to bytes
	signPublicKeyBytes, err := Base64StringToBytes(signKeyPair.PublicKeyBase64)
	if err != nil || signPublicKeyBytes == nil {
		return nil, errors.New("No valid KeyPair")
	}
	// signPublicKeyBase58 := base58.Encode(signPublicKeyBytes)

	encryptPublicKeyBytes, err := Base64StringToBytes(encryptKeyPair.PublicKeyBase64)
	if err != nil || encryptPublicKeyBytes == nil {
		return nil, errors.New("No valid KeyPair")
	}
	// encryptPublicKeyBase58 := base58.Encode(encryptPublicKeyBytes)
	// createdTime := time.Now()

	didKeyAgreement := []didDocument.Verification{
		{
			VerificationMethod: didDocument.VerificationMethod{
				ID:          "did:example:123456789abcdefghi#keys-1",
				Type:        "Secp256k1VerificationKey2018",
				Controller:  "did:example:123456789abcdefghi",
				Value:       encryptPublicKeyBytes,
			},
			Relationship: didDocument.KeyAgreement,
		},
	}

	eAuthentication := []didDocument.Verification{
		{
			VerificationMethod: didDocument.VerificationMethod{
				ID:          "did:example:123456789abcdefghi#key3",
				Controller:  "did:example:123456789abcdefghi",
				Type:        "RsaVerificationKey2018",
				Value:       signPublicKeyBytes,
			},
			Relationship: didDocument.Authentication,
			Embedded: true,
		},
	}

	eAssertion := []didDocument.Verification{
		{
			VerificationMethod: didDocument.VerificationMethod{
				ID:          "did:example:123456789abcdefghi#key3",
				Controller:  "did:example:123456789abcdefghi",
				Type:        "RsaVerificationKey2018",
				Value:       signPublicKeyBytes,
			},
			Relationship: didDocument.AssertionMethod,
			Embedded: true,
		},
	}

	// test public key
	ePubKey := []didDocument.VerificationMethod{
		{
			ID:          encryptKeyPair.PublicKeyDID,
			Controller:  encryptKeyPair.ControllerDID,
			Type:        encryptKeyPair.Type,
			Value:       encryptPublicKeyBytes,
		},
		{
			ID:          encryptKeyPair.PublicKeyDID,
			Controller:  encryptKeyPair.ControllerDID,
			Type:        encryptKeyPair.Type,
			Value:       signPublicKeyBytes,
		},
	}

	// test services
	eServices := []didDocument.Service{
		{
			ID:              signKeyPair.ControllerDID + "#" + "ipsSection" + "&" + "uhcCodeTag",
			Type:            "SocialWebInboxService",
			ServiceEndpoint: "https://api.unid.es/v1/gateway/",
			Properties:      map[string]interface{}{"some": map[string]interface{}{"value": "data1", "value2": "data2"}},
		},
		{
			ID:                       signKeyPair.ControllerDID + "#" + "did-communication",
			Type:                     "did-communication",
			Priority:                 0,
			RecipientKeys:            []string{"did:v1:uuid:<uuid>#Key2Base58"},
			RoutingKeys:              []string{"did:v1:uuid:<uuid>#Key2Base58"},
			ServiceEndpoint:          "https://agent.example.com/",
			Properties:               map[string]interface{}{},
		},
	}


	return &didDocument.Doc{
		Context:              []string{DidContext, SecurityContext},
		ID:                   signKeyPair.ControllerDID, // DIDMethod + UhcUserId
		VerificationMethod:   ePubKey,
		Service:              eServices,
		Authentication:       eAuthentication,
		AssertionMethod:      eAssertion,
		CapabilityDelegation: nil,
		CapabilityInvocation: nil,
		KeyAgreement:         didKeyAgreement,
		Created:              signKeyPair.CreatedAt,
		Updated:              &time.Time{},
		Proof:                nil,
	}, nil
}
