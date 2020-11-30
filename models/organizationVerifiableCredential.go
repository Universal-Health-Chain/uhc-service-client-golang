package models

import (
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"time"
)


var collectionNameOrganizationCredentials = "OrganizationVerifiableCredentials"

type OrganizationVP struct {
	Context               []string         `bson:"@context,omitempty" json:"@context,omitempty"`
	ID                    string           `bson:"id,omitempty" json:"id,omitempty"`
	Type                  []string         `bson:"type,omitempty" json:"type,omitempty"`
	VerifiableCredentials []OrganizationVC `bson:"verifiableCredential,omitempty" json:"verifiableCredential,omitempty"`
	Holder                string           `bson:"holder,omitempty" json:"holder,omitempty"`
	ListOfProof           []proof.Proof    `bson:"proof,omitempty" json:"proof,omitempty"`
}

type OrganizationVC struct {
	Context     []string              `bson:"@context,omitempty" json:"@context,omitempty"`
	ID          string                `bson:"id,omitempty" json:"id,omitempty"`
	Subject     FhirCredentialSubject `bson:"credentialSubject,omitempty" json:"credentialSubject,omitempty"`
	Type        []string              `bson:"type,omitempty" json:"type,omitempty"`
	Issuer      verifiable.Issuer     `bson:"issuer,omitempty" json:"issuer,omitempty"`
	Issued      *time.Time            `bson:"issuanceDate,omitempty" json:"issuanceDate,omitempty"`
	Expired     *time.Time            `bson:"expirationDate,omitempty" json:"expirationDate,omitempty"`
	ListOfProof []proof.Proof         `bson:"proof,omitempty" json:"proof,omitempty"`
	Status      *verifiable.TypedID   `bson:"credentialStatus,omitempty" json:"credentialStatus,omitempty"`
	Schemas     []verifiable.TypedID  `bson:"credentialSchema,omitempty" json:"credentialSchema,omitempty"`
	TermsOfUse     []verifiable.TypedID `bson:"termsOfUse,omitempty" json:"termsOfUse,omitempty"`
	RefreshService []verifiable.TypedID `bson:"refreshService,omitempty" json:"refreshService,omitempty"`
}

type FhirCredentialSubject struct {
	FhirOrganization    *fhir4.Organization              `bson:"fhir,omitempty" json:"fhir,omitempty"`
	UhcPublicExtensions *OrganizationPublicUHCExtensions `bson:"uhcPublicExtensions,omitempty" json:"uhcPublicExtensions,omitempty"` //dlt: no
}

type OrganizationVCResponse struct {
	Code    int               `bson:"code,omitempty" json:"code,omitempty"`
	Message string            `bson:"message,omitempty" json:"message,omitempty"`
	Data    []OrganizationVC `bson:"data,omitempty" json:"data,omitempty"`
}