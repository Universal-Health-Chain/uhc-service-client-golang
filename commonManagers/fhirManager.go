package commonManagers

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
	"time"
)

const (
	hl7CodeSystemSNOMED = "http://snomed.info/sct"
	hl7CodeSystemLOINC = "http://loinc.org"
)

func uhcMessageByFhirMessage(fhirMessageEncryptedBase64, recipientUhcUserId, userId string) (uhcMessage *models.MessageUHC){

	id, _ := uuid.NewRandom()
	idStr := id.String()	// uhcMessage.ID = id.String() fails
	messageUHC := models.MessageUHC{
		ToUserId:   recipientUhcUserId,
		FromUserId: userId,
		ID: idStr,			// id.String() fails
		Status : "UNREAD",
		UHCPayload: &models.UHCPayload{
			PayloadBase64: fhirMessageEncryptedBase64,
			EncryptedPayload: true,
		},
	}
	return &messageUHC
}

func FhirDocReferenceByAttachedBytesPDF(fileBytes *[]byte, mimeType, language, categoryCodeSNOMED *string) (*fhir4.DocumentReference, error) {
	randomUuid, _ := uuid.NewRandom()
	idStr := randomUuid.String()

	// get legacy hash SHA1 for the attached bytes
	sha1,err := getHashLegacySHA1(*fileBytes)
	if err != nil {return &fhir4.DocumentReference{}, err}

	dataBase64 := BytesToBase64String(*fileBytes)
	size := len(*fileBytes)
	time := time.Now().Format(time.RFC3339)

	docStatus := fhir4.CompositionStatusFinal

	documentReferenceContent := fhir4.DocumentReferenceContent{
		Attachment: fhir4.Attachment{
			ContentType: 	mimeType,
			Language:    	language,
			Data:        	&dataBase64,
			Size: 			&size,
			Hash:        	&sha1,	// lecagy SHA1 in FHIR.Attachment.Hash
			Creation:    	&time,
		},
	}

	categoryCoding := &fhir4.Coding{Code: categoryCodeSNOMED}
	categorySystem := hl7CodeSystemSNOMED
	categoryUserSelected := false
	categoryCoding.System = &categorySystem
	categoryCoding.UserSelected = &categoryUserSelected

	categoryCodeable := fhir4.CodeableConcept{}
	categoryCodeable.Coding = append(categoryCodeable.Coding, *categoryCoding)

	fhirDocumentReference := &fhir4.DocumentReference{
		Id: &idStr,
		// Identifier: put the Id here,
		// Author:  reference as did:v1:uhcUserId or did:v1:uhcDeviceId,
		// Type:    param type,
		// Context: param facilityType
		Language:   language,
		Status:    	fhir4.DocumentReferenceStatusCurrent,
		DocStatus:	&docStatus,
		Date:       &time,
		Content:    nil,
	}
	fhirDocumentReference.Content = append(fhirDocumentReference.Content, documentReferenceContent)
	return fhirDocumentReference, nil
}