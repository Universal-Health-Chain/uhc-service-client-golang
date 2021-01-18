package models

import (
	"encoding/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
)

// A UHC form includes the neccesary fields to create both a FHIR Bundle (such as mediaContents) and a UHC Biography Entry
type BiographyUHC struct {
	ID                	string      // uuid
	UhcUserId			string      // Who is the owner of this registry
	ResourceLanguage	string      // Language of the content
	Title             	string      // BiographyEntry.title replaces health_entry.title
	Description			string      // BiographyEntry.description replaces health_entry.description
	Section				string      // e.g. Health/Laboratory Results
	// frontendPath      string      // BiographyEntry.frontendPath replaces health_entry.entry_type (e.g. "Analysis")
	UhcCodeTag			[]string
	LastUpdated       	string      // date time in ISO format
	// backupUrl     	string
	SectionUSCDI   		string  // e.g. Laboratory
	SectionIPS     		string  // e.g. Results
	presentation 		PresentationWithBundleInVC
}

type PresentationWithBundleInVC struct {
	Context			[]string			`json:"@context,omitempty"`
	// CustomContext	[]interface{}
	ID				string				`json:"id,omitempty"`
	Type          	[]string			`json:"type,omitempty"`
	Credential		[]CredentialFHIR	`json:"verifiableCredential"`
	Holder        	string				`json:"holder,omitempty"`
	Proof        	[]proof.Proof		`json:"proof,omitempty"`
	CustomFields  	CustomFields		`json:"-"`
}

type CredentialFHIR struct {
	Context       []string							`json:"@context,omitempty"`
	ID            string							`json:"id,omitempty"`
	Types         []string							`json:"type,omitempty"`
	// Issuer         Issuer
	Issued         string
	Expired        string
	Proofs         []proof.Proof
	// Status         *TypedID
	// Schemas        []TypedID
	// Evidence       Evidence
	// TermsOfUse     []TypedID
	// RefreshService []TypedID
	// CustomFields CustomFields
	CredentialVerifiableFHIR			`json:"credentialSubject,omitempty"`
}

type CredentialVerifiableFHIR struct{
	BundleFHIR	fhir4.Bundle		`json:"fhir,omitempty" bson:"fhir,omitempty"`
}

// rawCredential is a basic verifiable credential.
type rawCredential struct {
	Context        interface{}                    `json:"@context,omitempty"`
	ID             string                         `json:"id,omitempty"`
	Type           interface{}                    `json:"type,omitempty"`
	Subject        json.RawMessage                `json:"credentialSubject,omitempty"`
	Issued         *util.TimeWithTrailingZeroMsec `json:"issuanceDate,omitempty"`
	Expired        *util.TimeWithTrailingZeroMsec `json:"expirationDate,omitempty"`
	Proof          json.RawMessage                `json:"proof,omitempty"`
	// Status         *TypedID                       `json:"credentialStatus,omitempty"`
	Issuer         json.RawMessage                `json:"issuer,omitempty"`
	Schema         interface{}                    `json:"credentialSchema,omitempty"`
	// Evidence       Evidence                       `json:"evidence,omitempty"`
	TermsOfUse     json.RawMessage                `json:"termsOfUse,omitempty"`
	RefreshService json.RawMessage                `json:"refreshService,omitempty"`

	// All unmapped fields are put here.
	CustomFields `json:"-"`
}

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}