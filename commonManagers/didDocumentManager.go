/* Copyright 2021 Fundación UNID */
package commonManagers

import (
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
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

	/*
	eService := didDocument.Service{
		ID:              signKeyPair.PublicKeyInfo.ControllerDID + "#" + "did-communication",
		Type:            "did-communication",
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{signKeyPair.PublicKeyInfo.ControllerDID},
		Priority:        0,
	}*/
	// createdTime := time.Now()
	
	didAuthentication := []didDocument.VerificationMethod{
		{
			PublicKey: *didDocument.NewPublicKeyFromBytes(
				signKeyPair.PublicKeyDID,
				signKeyPair.Type,
				signKeyPair.ControllerDID,
				signPublicKeyBytes),
			Relationship: didDocument.Authentication,
		},
	}

	didKeyAgreement := []didDocument.VerificationMethod{
		{
			PublicKey: *didDocument.NewPublicKeyFromBytes(
				encryptKeyPair.PublicKeyDID,
				encryptKeyPair.Type,
				encryptKeyPair.ControllerDID,
				encryptPublicKeyBytes),
			Relationship: didDocument.KeyAgreement,
		},
	}

	didPublicKeys := []didDocument.PublicKey{
		{
			ID:         signKeyPair.PublicKeyDID,	// signKeyPair.ControllerDID + "#" + signKeyPair.ID
			Controller: signKeyPair.ControllerDID,	// DIDMethod + UhcUserId
			Type:       signKeyPair.Type,
			Value:      signPublicKeyBytes,
		},
		{
			ID:         encryptKeyPair.PublicKeyDID,	// encryptKeyPair.ControllerDID + "#" + encryptKeyPair.ID
			Controller: encryptKeyPair.ControllerDID,	// DIDMethod + UhcUserId
			Type:       encryptKeyPair.Type,
			Value:      encryptPublicKeyBytes,
		},
	}

	return &didDocument.Doc{
		Context:              []string{DidContext, SecurityContext},
		ID:                   signKeyPair.ControllerDID,	// DIDMethod + UhcUserId
		PublicKey:            didPublicKeys,
		Authentication:       didAuthentication,
		KeyAgreement:         didKeyAgreement,
		Created:              signKeyPair.CreatedAt,
		// AssertionMethod:      nil,
		// CapabilityDelegation: nil,
		// CapabilityInvocation: nil,
		// Service:              eService, // []didDocument.Service{service},
		// Updated:              nil,
		// Proof:                nil,
	}, nil
}
