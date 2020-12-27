package commonManagers

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
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

const didMethod = "v1"

// VDRI implements did:key method support.
type VDRI struct {
}

// New returns new instance of VDRI that works with did:key method.
func New() *VDRI {
	return &VDRI{}
}

// Accept accepts did:key method.
func (v *VDRI) Accept(method string) bool {
	return method == didMethod
}

// Store saves a DID Document along with user key/signature.
func (v *VDRI) Store(doc *didDocument.Doc, by *[]vdri.ModifiedBy) error {
	return nil
}

// Close frees resources being maintained by VDRI.
func (v *VDRI) Close() error {
	return nil
}

