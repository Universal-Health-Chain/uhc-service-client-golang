package commonManagers

import (
	didDocument "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	documentSigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
)

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
