package commonManagers

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"time"
)

func CreateEd25519SignKeyPair(walletId string, uhcOwnerId string, purposes []string, tag string) (*models.Key, error) {
	_, err := uuid.Parse(walletId)
	if err != nil {return nil, errors.New("WalletId is mandatory")}

	_, err = uuid.Parse(uhcOwnerId)
	if err != nil {return nil, errors.New("Owner ID is mandatory")}

	if len(purposes) == 0 { purposes = []string{""}}	// provisional while Capability isn't an array to avoid nil errors

	// It generates public and private signing keys for Ed25519Signature2018
	publicSingKeyBytes, secretSignKeyBytes, err := ed25519.GenerateKey(nil)
	if err != nil {return nil, err}

	// ownerDid and purposes should be optional
	uuidRandomv4, _ := uuid.NewRandom()
	uuidv4String := uuidRandomv4.String()
	timestamp := time.Now()

	signKeyPair := &models.Key{
		ID:        		uuidv4String,
		WalletKeyId:	walletId,
		Tag:			tag,
		Type:           Ed25519KeyType,		// "Ed25519VerificationKey2018"
		CreatedAt:      &timestamp,
		// Expires:        &time.Time{},
		Controller:     DIDMethod + uhcOwnerId, // not uhcOwnerId,
		DidKeyId:       DIDMethod + uhcOwnerId + "#" + uuidv4String,
		PublicKeyBase64:BytesToBase64String(publicSingKeyBytes),
		PrivateKeyBase64:BytesToBase64String(secretSignKeyBytes),
		Capability: 	purposes[0],		// TODO: Change to Purposes []string
	}

	return signKeyPair, nil
}

func CreateBlockchainDidDocument(keyId string, subjectPublicSingKeyBytes []byte) (*didDocument.Doc, error){

	publicSignKeyBase58 := base58.Encode(subjectPublicSingKeyBytes)
	if publicSignKeyBase58 == "" { return nil, errors.New("Cannot get public key in base 58 format") }

	uuidRandomv4, _ := uuid.NewRandom()
	uuidv4String := uuidRandomv4.String()
	timestamp := time.Now()

	hexDecodeValue, _ := hex.DecodeString("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
	// doc, err := didDocument.ParseDocument([]byte(DidForTesting))

	// authentication
	eAuthentication := []didDocument.VerificationMethod{
		{PublicKey: *didDocument.NewPublicKeyFromBytes(
			"did:example:123456789abcdefghi#keys-1",
			"Secp256k1VerificationKey2018",
			"did:example:123456789abcdefghi",
			base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")),
			Relationship: didDocument.Authentication,
		},
		{PublicKey: didDocument.PublicKey{
			ID:         "did:example:123456789abcdefghs#key3",
			Controller: "did:example:123456789abcdefghs",
			Type:       "RsaVerificationKey2018",
			Value:      hexDecodeValue}, Relationship: didDocument.Authentication, Embedded: true}}
	// require.Equal(t, eAuthentication, doc.Authentication)

	// public key
	ePubKey := []didDocument.PublicKey{
		{ID: "did:example:123456789abcdefghi#keys-1",
			Controller: "did:example:123456789abcdefghi",
			Type:       "Secp256k1VerificationKey2018",
			Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
		},
	}
	// require.Equal(t, ePubKey, doc.PublicKey)

	// services
	eServices := []didDocument.Service{
		{ID: "did:example:123456789abcdefghi#inbox",
			Type:            "SocialWebInboxService",
			ServiceEndpoint: "https://social.example.com/83hfh37dj",
			Properties:      map[string]interface{}{"spamCost": map[string]interface{}{"amount": "0.50", "currency": "USD"}},
		},
		{ID: "did:example:123456789abcdefghi#did-communication",
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{"did:example:123456789abcdefghi#key2"},
			RoutingKeys:     []string{"did:example:123456789abcdefghi#key2"},
			ServiceEndpoint: "https://agent.example.com/",
			Properties:      map[string]interface{}{},
		},
	}
	// require.EqualValues(t, eServices, doc.Service)

	// publicKey := &ed25519.PublicKey(subjectPublicSingKeyBytes)

	didDoc := &didDocument.Doc{
		ID: uuidv4String,
		Created: &timestamp,	// .Format(time.RFC3339)
		PublicKey: ePubKey,
		Authentication: eAuthentication,
		Service: eServices,
	}
	return didDoc, nil
}

// DID Document capabilites, Verification method and KeyAgreement: https://whitepaper.fission.codes/identity/did-doc
const DidForTesting = `
{
  "@context": "https://w3id.org/did/v1",
  "id": ""did:v1:uuid:804c6ac3-ce3b-46ce-b134-17175d5bee74",
  "publicKey": [{
    "id": ""publicsignEHR1",
    "type": "Ed25519VerificationKey2018",
    "controller": ""did:v1:uuid:804c6ac3-ce3b-46ce-b134-17175d5bee74#publicsignEHR1",
    "publicKeyBase58": "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
  }],
  "authentication": ["publicsignEHR1"],
  "assertionMethod": ["publicsignEHR1"],
  "capabilityDelegation": ["publicsignEHR1"],
  "capabilityInvocation": ["publicsignEHR1"],
  "keyAgreement": [{
    "id": "publickaCONN1",
    "type": "X25519KeyAgreementKey2019",
    "controller": ""did:v1:uuid:804c6ac3-ce3b-46ce-b134-17175d5bee74#publickaCONN1",
    "publicKeyBase58": "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
  }]
}`
