package models

import (
	"encoding/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
)

// A UHC form includes the neccesary fields to create both a FHIR Bundle (such as mediaContents) and a UHC Biography Entry
type BiographyUHC struct {
	ID               string `json:"id,omitempty" bson:"id,omitempty"`
	UhcUserId        string `json:"uhcUserId,omitempty" bson:"uhcUserId,omitempty"`
	ResourceLanguage string `json:"resourceLanguage,omitempty" bson:"resourceLanguage,omitempty"`
	Title            string `json:"title,omitempty" bson:"title,omitempty"`
	Description      string `json:"description,omitempty" bson:"description,omitempty"`
	Section          string `json:"section,omitempty" bson:"section,omitempty"`
	// frontendPath      string      // BiographyEntry.frontendPath replaces health_entry.entry_type (e.g. "Analysis")
	UhcCodeTags []string `json:"uhcCodeTags,omitempty" bson:"uhcCodeTags,omitempty"`
	LastUpdated string   `json:"lastUpdated,omitempty" bson:"lastUpdated,omitempty"`
	// backupUrl     	string
	SectionUSCDI string                     `json:"sectionUSCDI,omitempty" bson:"sectionUSCDI,omitempty"`
	SectionIPS   string                     `json:"sectionIPS,omitempty" bson:"sectionIPS,omitempty"`
	Presentation PresentationWithBundleInVC `json:"presentation,omitempty" bson:"presentation,omitempty"`
}

type PresentationWithBundleInVC struct {
	Context []string `json:"@context,omitempty"`
	// CustomContext	[]interface{}
	ID           string           `json:"id,omitempty"`
	Type         []string         `json:"type,omitempty"`
	Credential   []CredentialFHIR `json:"verifiableCredential"`
	Holder       string           `json:"holder,omitempty"`
	Proof        []proof.Proof    `json:"proof,omitempty"`
	CustomFields CustomFields     `json:"-"`
}

type CredentialFHIR struct {
	Context []string `json:"@context,omitempty"`
	ID      string   `json:"id,omitempty"`
	Types   []string `json:"type,omitempty"`
	// Issuer         Issuer
	Issued  string
	Expired string
	Proofs  []proof.Proof
	// Status         *TypedID
	// Schemas        []TypedID
	// Evidence       Evidence
	// TermsOfUse     []TypedID
	// RefreshService []TypedID
	// CustomFields CustomFields
	CredentialVerifiableFHIR `json:"credentialSubject,omitempty"`
}

type CredentialVerifiableFHIR struct {
	BundleFHIR fhir4.Bundle `json:"fhir,omitempty" bson:"fhir,omitempty"`
}

// rawCredential is a basic verifiable credential.
type rawCredential struct {
	Context interface{}                    `json:"@context,omitempty"`
	ID      string                         `json:"id,omitempty"`
	Type    interface{}                    `json:"type,omitempty"`
	Subject json.RawMessage                `json:"credentialSubject,omitempty"`
	Issued  *util.TimeWithTrailingZeroMsec `json:"issuanceDate,omitempty"`
	Expired *util.TimeWithTrailingZeroMsec `json:"expirationDate,omitempty"`
	Proof   json.RawMessage                `json:"proof,omitempty"`
	// Status         *TypedID                       `json:"credentialStatus,omitempty"`
	Issuer json.RawMessage `json:"issuer,omitempty"`
	Schema interface{}     `json:"credentialSchema,omitempty"`
	// Evidence       Evidence                       `json:"evidence,omitempty"`
	TermsOfUse     json.RawMessage `json:"termsOfUse,omitempty"`
	RefreshService json.RawMessage `json:"refreshService,omitempty"`

	// All unmapped fields are put here.
	CustomFields `json:"-"`
}

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}
