package models

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type ApiDocumentReferenceClaimsJWT struct {
	jwt.StandardClaims
	ApiDocumentReferenceOptions
}

type ApiDocumentReferenceOptions struct {
	// UHC specific
	ConnectionUHC 			string	// UHC private connection e.g. http://api.unid.es/v1/connection/987
	DocStatus            	string	// e.g. "final", "preliminary", "amended", "entered-in-error"
	TextTitle				string	// Title in plain text filed by a practitioner or device (no xhtml)
	FileSHA1Hex           	string	// Legacy SHA1 digest in hexadecimal (FHIR Attachment Hash is Base64 SHA1,not Hex)
	FileSize              	string	// Number of bytes of content
	FileDate              	string	// Number of bytes of content
	// DocumentReference
	Authenticator			string	// Who signs the data e.g. http://unid.es/api/v1/fhir/R4/Person/123
	Author					string	// Who created the data e.g. http://unid.es/api/v1/fhir/R4/Practitioner/234
	CategoryLOINC 			string	// IPS / USCDI section (High-level kind of clinical document) e.g. "http://loinc.org|11369-6" (History of Immunization)
	ContentMimeType			string  // e.g. "application/pdf"
	CustodianOrganization	string	// Organization which maintains the document e.g. http://unid.es/api/v1/fhir/R4/Organization/345
	DateTime              	string	// When was created (FHIR dateTime stored as FHIR ISO format)
	FacilityTypeSNOMED		string	// Kind of facility where subject was seen
	FormatCodeSet   		string	// e.g. "urn:ihe:pcc:xphr:2007" or "urn:ihe:pcc:ic:2008"
	Identifier				string	// Master Version Specific Identifier
	Language				string	// Human language of attached file content (BCP-47)
	Location				string	// URI where the data can be found
	Period       			string	// Time service that is being documented e.g. "date=eq2010-01-01&date=eq2011-12-31"
	PracticeSettingSNOMED	string	// Clinical Specialty: details about where the content was created
	SecurityLabelHL7		string	// Document security-tag e.g. "http://terminology.hl7.org/CodeSystem/v3-ActReason|HLEGAL"
	StatusHL7             	string	// Current status (accepted values depends on each specific FHIR resource)
	Subject					string	// Who/what is the subject of the document
	TypeLOINC             	string	// Additional more precise type of clinical document filed by practitioner or device
}

// Method GetDocumentReferenceApiHeaderTags returns the valid headers to be used for a FHIR DocumentReference API
func (apiDocRef *ApiDocumentReferenceOptions) GetDocumentReferenceApiHeaderTags() ApiDocumentReferenceOptions{
	documentReferenceApiHeaderTags := &ApiDocumentReferenceOptions{
		ConnectionUHC:         	UhcApiConnection, // ID of an existing connection
		DocStatus:             	UhcApiDocStatus,
		TextTitle:				UhcApiTextTile,
		FileSHA1Hex:           	UhcApiSHA1Hex,
		FileSize:              	UhcApiBytesSize,
		FileDate:              	UhcApiCreationDateTime,	// Date the attached PDF, may be different to DocumentReference date
		Authenticator:         	FhirApiAuthenticator,
		Author:                	FhirApiAuthor,
		CategoryLOINC:         	FhirApiCategory,
		ContentMimeType:       	FhirApiMimeContentType,
		CustodianOrganization: 	FhirApiOrganizationCustodian,
		DateTime:              	FhirApiDate,	// Date of the DocumentReference resource, may be different to the PDF date
		FacilityTypeSNOMED:    	FhirApiFacilityType,
		FormatCodeSet:         	FhirApiFormatCodeSet,
		Identifier:            	FhirApiIdentifier,
		Language:              	FhirApiLanguage,
		Location:              	FhirApiLocation,
		Period:                	FhirApiPeriod,
		PracticeSettingSNOMED: 	FhirApiPracticeSetting,
		SecurityLabelHL7:      	FhirApiSecurityLabel,
		StatusHL7:             	FhirApiStatus,
		Subject:               	FhirApiSubject,
		TypeLOINC:             	FhirApiType,
	}
	return *documentReferenceApiHeaderTags
}

// Method BaseDocumentReferenceByApiHeaders returns a BaseDocumentReference created with the ApiOptions received by an API
func (apiDocRef *ApiDocumentReferenceOptions) GetBaseDocumentReferenceByRequestHeaders(r *http.Request) BaseDocumentReference {
	docRefApiOptions := &ApiDocumentReferenceOptions{}
	docRefHeaders := docRefApiOptions.GetDocumentReferenceApiHeaderTags()

	textTitle := r.Header.Get(docRefHeaders.TextTitle)
	language := r.Header.Get(docRefHeaders.Language)
	contentMimeType := r.Header.Get(docRefHeaders.ContentMimeType)
	// statusCodeHL7 := r.Header.Get(docRefHeaders.StatusHL7)         // TODO: function to split and return fhir4.DocumentReferenceStatus
	// docStatus := r.Header.Get(docRefHeaders.DocStatus)             // TODO: function to split and return fhir4.CompositionStatus
	categoryCodeLOINC := r.Header.Get(docRefHeaders.CategoryLOINC) // TODO: function to split and return only the code

	baseDocRef := BaseDocumentReference{
		TextTitle: &textTitle,
		Language:  &language,
		// Status:               statusCodeHL7,
		// DocStatus:            docStatus,
		CategoryLOINC:          &categoryCodeLOINC,
		Date:                   nil,
		FileDataB64:            nil,
		FileMimeContentType:    &contentMimeType,
		FileHexSHA1:            nil,
		FileSize:               nil,
		TypeLOINC:              nil,
		ContextPeriodStart:     nil,
		ContextPeriodEnd:       nil,
		ContentFormatCodeSet:   nil,
		FacilitySNOMED:         nil,
		PracticeSettingSNOMED:  nil,
		Description:            nil,
		SubjectUHC:             nil,
		AuthenticatorReference: nil,
		CustodianReference:     nil,
	}
	return baseDocRef
}

