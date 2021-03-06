/* Copyright 2021 Fundación UNID */
package models

import (
	b64 "encoding/base64"
	"errors"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
	"github.com/google/uuid"
	"time"
)

type BaseDocumentReference struct {
	TextTitle            *string                        // Text title of the resource (FHIR text is xhtml) filed by a practitioner or device
	Language             *string                        // Language of the document
	Status               *fhir4.DocumentReferenceStatus // Fix to "current" when creating (other are: superseded, entered-in-error)
	DocStatus            *fhir4.CompositionStatus       // Fixed to "final" (other are: preliminary, amended, entered-in-error)
	CategoryLOINC        *string                        // The health history section goes to array[0], e.g. "11369-6" (History of Immunization)
	Date                 *string                        // When the document was created
	FileDataB64          *string                        // The data encoded in Base64 format
	FileMimeContentType  *string                        // e.g. application/pdf
	FileHexSHA1          *string                        // Legacy SHA1 digest in hexadecimal (FHIR Attachment is BASE64 SHA1)
	FileSize             *int                           // Number of bytes of content
	TypeLOINC            *string                        // Kind of document or Health Section, e.g.: "48765-2" (Allergies and adverse reactions Document)
	ContextPeriodStart   *string                        // FHIR dateTime: time of service that is being documented
	ContextPeriodEnd     *string                        // FHIR dateTime: end of time service that is being documented
	ContentFormatCodeSet *string                        // e.g. "urn:ihe:pcc:xphr:2007" or "urn:ihe:pcc:ic:2008"
	FacilitySNOMED			*string                        // Kind of facility where patient was seen
	PracticeSettingSNOMED	*string                       // Clinical Specialty: details about where the content was created
	// SecurityLabelsFHIR   *[]string // Document security-tags
	Description            	*string   	// Description generated by Practitioner / Device
	SubjectUHC             	*string   	// Who/what is the subject of the document
	AuthorReference       	*string		// Who and/or what authored the document
	AuthenticatorReference 	*string		// Who/what authenticated the document
	CustodianReference     	*string 	// Organization which maintains the document
}

func (docRefParams *BaseDocumentReference) GetParams() *BaseDocumentReference {
	return docRefParams
}

// Method CreateDocumentReferenceFHIR creates a FHIR DocumentReference using the initialized BaseDocumentReference and given fileBytes
func (docRefParams *BaseDocumentReference) CreateDocumentReferenceFHIR(fileBytes *[]byte) (fhir4.DocumentReference, error) {
	if fileBytes != nil {
		// It checks and / or puts the size of the given bytes
		size := len(*fileBytes)
		if docRefParams.FileSize != nil {
			if &size != docRefParams.FileSize {return fhir4.DocumentReference{}, errors.New("file size mismatch")}
		} else {
			docRefParams.FileSize = &size
		}

		// It checks and / or puts the SHA1 digest of the given bytes
		sha1 := GetHashLegacySHA1AsHexString(*fileBytes)	// Get legacy hash SHA1 for the attached bytes
		if docRefParams.FileHexSHA1 != nil {
			if &sha1 != docRefParams.FileHexSHA1 {return fhir4.DocumentReference{}, errors.New("file SHA1 mismatch")}
		} else {
			docRefParams.FileHexSHA1 = &sha1
		}

		// It encodes and puts the bytes in Base64
		dataB64 := b64.StdEncoding.EncodeToString(*fileBytes)
		docRefParams.FileDataB64 = &dataB64
	}

	// It checks and puts the current data if it does not exists
	if docRefParams.Date == nil {
		time := time.Now().Format(time.RFC3339)
		docRefParams.Date = &time
	}

	// It checks the status of the document and puts "final" if it does not exists
	if docRefParams.DocStatus == nil {
		docStatus := fhir4.CompositionStatusFinal
		docRefParams.DocStatus = &docStatus
	}

	// It creates a FHIR.DocumentReference.Content to be appended to the array of FHIR.DocumentReference.Content
	documentReferenceContent := fhir4.DocumentReferenceContent{
		Attachment: fhir4.Attachment{
			ContentType: 	docRefParams.FileMimeContentType,
			Language:    	docRefParams.Language,
			Size: 			docRefParams.FileSize,
			Data: 			docRefParams.FileDataB64,
			Hash:        	docRefParams.FileHexSHA1,	// lecagy SHA1 in FHIR.Attachment.Hash
			Creation:    	docRefParams.Date,
		},
	}

	// It creates a FHIR.DocumentReference.Category.Coding to be appended to the array of FHIR.DocumentReference.Category
	categoryCoding := &fhir4.Coding{Code: docRefParams.CategoryLOINC}
	categorySystem := HL7CodeSystemSNOMED
	categoryUserSelected := false
	categoryCoding.System = &categorySystem
	categoryCoding.UserSelected = &categoryUserSelected

	categoryCodeable := fhir4.CodeableConcept{}
	categoryCodeable.Coding = append(categoryCodeable.Coding, *categoryCoding)

	// It creates the FHIR.DocumentReference and then puts the above created objects
	randomUuid, _ := uuid.NewRandom()
	idStr := randomUuid.String()
	fhirDocumentReference := &fhir4.DocumentReference{
		Id: &idStr,
		// Identifier: put the Id here,
		// Author:  reference as did:v1:uhcUserId or did:v1:uhcDeviceId,
		// Type:    param type,
		// Context: param facilityType
		Language:   docRefParams.Language,
		Status:    	fhir4.DocumentReferenceStatusCurrent,
		DocStatus:	docRefParams.DocStatus,
		Date:       docRefParams.Date,
		Content:    nil,
	}

	// It adds the above created elements to the FHIR DocumentReference
	fhirDocumentReference.Content = append(fhirDocumentReference.Content, documentReferenceContent)
	fhirDocumentReference.Category = append(fhirDocumentReference.Category, categoryCodeable)

	return *fhirDocumentReference, nil
}