package models

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
)

type BiographyUHC struct {
	ID               string `json:"id,omitempty" bson:"id,omitempty"`	// It should be the same as...
	UhcUserId        string `json:"uhcUserId,omitempty" bson:"uhcUserId,omitempty"`
	ResourceLanguage string `json:"resourceLanguage,omitempty" bson:"resourceLanguage,omitempty"`
	Title            string `json:"title,omitempty" bson:"title,omitempty"`
	Description      string `json:"description,omitempty" bson:"description,omitempty"`
	Section          string `json:"section,omitempty" bson:"section,omitempty"`
	UhcCodeTags 	[]string`json:"uhcCodeTags,omitempty" bson:"uhcCodeTags,omitempty"`
	LastUpdated 	string	`json:"lastUpdated,omitempty" bson:"lastUpdated,omitempty"`
	SectionUSCDI 	string	`json:"sectionUSCDI,omitempty" bson:"sectionUSCDI,omitempty"`
	SectionIPS   	string	`json:"sectionIPS,omitempty" bson:"sectionIPS,omitempty"`
	Presentation PresentationWithBundleInVC `json:"presentation,omitempty" bson:"presentation,omitempty"`
}

type PresentationWithBundleInVC struct {
	Context			[]string 			`json:"@context,omitempty"`
	ID           	string           	`json:"id,omitempty" bson:"id,omitempty"`
	Type         	[]string         	`json:"type,omitempty bson:"type,omitempty"" `
	Holder       	string           	`json:"holder,omitempty" bson:"holder,omitempty"`
	Proof        	[]proof.Proof    	`json:"proof,omitempty" bson:"proof,omitempty"`
	CustomFields 	CustomFields     	`json:"-" bson:"customFields,omitempty"`	// All unmapped fields are put here.
	Credential   	[]CredentialFHIR	`json:"verifiableCredential bson:"verifiableCredential,omitempty""`
}

type CredentialFHIR struct {
	Context 				[]string 				`json:"@context,omitempty" bson:"@context,omitempty"`
	ID      				string   				`json:"id,omitempty" bson:"id,omitempty"`
	Types   				[]string 				`json:"type,omitempty" bson:"type,omitempty"`
	Issuer					verifiable.Issuer		`json:"issuer,omitempty" bson:"issuer,omitempty"`
	Issued  				string					`json:"issuanceDate,omitempty" bson:"issuanceDate,omitempty"`
	Expired 				string					`json:"expirationDate,omitempty" bson:"expirationDate,omitempty"`
	Proofs  				[]proof.Proof			`json:"proof,omitempty" bson:"proof,omitempty"`
	Status      			*verifiable.TypedID		`json:"credentialStatus,omitempty" bson:"credentialStatus,omitempty"`
	Schemas					[]verifiable.TypedID	`json:"credentialSchema,omitempty" bson:"credentialSchema,omitempty"`
	Evidence       			verifiable.Evidence		`json:"evidence,omitempty" bson:"evidence,omitempty"`
	TermsOfUse     			[]verifiable.TypedID	`json:"termsOfUse,omitempty" bson:"termsOfUse,omitempty"`
	RefreshService			[]verifiable.TypedID	`json:"refreshService,omitempty" bson:"refreshService,omitempty"`
	CustomFields 			CustomFields			`json:"-" bson:"customFields,omitempty"` // All unmapped fields are put here.
	CredentialSubjectFHIR	CredentialVerifiableFHIR`json:"credentialSubject,omitempty" bson:"credentialSubject,omitempty"`
}

type CredentialVerifiableFHIR struct {
	BundleFHIR fhir4.Bundle `json:"fhir,omitempty" bson:"fhir,omitempty"`
}

type CustomFields map[string]interface{} // CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not mapped to the struct fields.
