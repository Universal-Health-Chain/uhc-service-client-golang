/* Copyright 2021 Fundación UNID */
package commonManagers

// FHIR JSON Canonization Rules: https://www.hl7.org/fhir/json.html#canonical
// FHIR JSON Signature Rules: https://www.hl7.org/fhir/datatypes.html#JSON
// Invoking REST operations via FHIR messages: https://www.hl7.org/fhir/datatypes.html#JSON
// Asynchronous Messaging using REST API: https://www.hl7.org/fhir/datatypes.html#JSON

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
	"time"
)

const(
	MessagingSystemName 	= "UNID"
	MessagingSoftwareName 	= "UHC"
	MessagingEventSystem 	= "http://unid.es/fhir/message-events"
)

const (
	IPSCompositionMetaProfile 		= "http://hl7.org/fhir/uv/ips/StructureDefinition/Composition-uv-ips"
	IPSCompositionIdentifierSystem	= "urn:oid:2.16.724.4.8.10.200.10"
	IPSCompositionTypeCodeLOINC		= "60591-5"

	HL7SystemValueSetDocTypeCodes	= "http://hl7.org/fhir/ValueSet/doc-typecodes"
	HL7ValueSetDocTypeMedicalRecords= "11503-0"

	HL7SystemValueSetActCodeSystem	= "http://terminology.hl7.org/CodeSystem/v3-ActStatus"
	HL7ValueSetActCodeCareProvision	= "PCPR"	// for IPS document composition
	HL7ValueSetActCodeEncounter		= "ENC"
	HL7ValueSetActCodeProcedure		= "PROC"
	HL7ValueSetActCodeObservation	= "OBS"
	HL7ValueSetActCodeClinicalDoc	= "DOCCLIN"	// Clinical document
	HL7ValueSetActCodeAct			= "ACT"
	// Act is record of something that is being done, has been done, can be done, or is intended or requested to be done:
	// (1) a clinical observation, (2) an assessment of health condition (such as problems and diagnoses),
	// (3) healthcare goals, (4) treatment services (such as medication, surgery, physical and psychological therapy),
	// (5) assisting, monitoring or attending, (6) training and education services to patients and their next of kin,
	// (7) and notary services (such as advanced directives or living will), (8) editing and maintaining documents, and many others
)

type FhirBundleManager struct {}

func (fhirManager *FhirBundleManager) createEmptyBundle(bundleType fhir4.BundleType) fhir4.Bundle{
	randomUuid, _ := uuid.NewRandom()
	idStr := randomUuid.String()

	fhirBundle := &fhir4.Bundle{
		Id:            &idStr,
		Type:          bundleType,
	}
	return *fhirBundle
}

// Method AddRawResourcesToBundle adds resources to FHIR Bundle with 'fullUrl'
func (fhirManager *FhirBundleManager) AddRawResourcesToBundle(fhirBundle *fhir4.Bundle, rawResources *[]json.RawMessage) {
	if rawResources==nil || len(*rawResources)<1 { return }
	// It loop for each json.RawMessage to get the 'id'
	for _, resourceRaw := range *rawResources {	// for {key}, {value} := range {list}
		bundleEntry := fhir4.BundleEntry{}
		// It gets the 'id' (if exists) from each json.RawMessage
		var resourceJsonMap map[string]interface{}
		err := json.Unmarshal(resourceRaw, &resourceJsonMap)
		if err == nil {
			// it gets the 'id' (if exists), creates and puts 'fullUrl'
			resourceIdIface, ok := resourceJsonMap["id"]
			if ok {
				id := fmt.Sprintf("%v", resourceIdIface)
				fullUrl := "urn:uuid:" + id
				bundleEntry.FullUrl = &fullUrl
			}
		}
		// It adds the resource to the BundleEntry and the BundleEntry to the FHIR.Bundle
		bundleEntry.Resource = resourceRaw
		fhirBundle.Entry = append(fhirBundle.Entry, bundleEntry)
	}
}

// Method AddRawResourceToBundle puts 'urn:uuid:<resourceID>' to BundleEntry.FullUrl
func (fhirManager *FhirBundleManager) AddRawResourceToBundle(fhirBundle *fhir4.Bundle, resourceRaw *json.RawMessage) {
	rawResources := []json.RawMessage{*resourceRaw}
	fhirManager.AddRawResourcesToBundle(fhirBundle, &rawResources)
	return
	/*
		newBundleEntry := fhir4.BundleEntry{ Resource: *resourceRaw }
		if resourceID != nil {
			fullURN := "urn:uuid:" + *resourceID
			newBundleEntry.FullUrl = &fullURN
		}
		fhirBundle.Entry = append(fhirBundle.Entry, newBundleEntry)
		return nil
	*/
}

// Method createBundleWithTypeAndResources creates a FHIR Bundle with the specified type and resources, adding 'fullUrl' to each BundleEntry from resource.id
func (fhirManager *FhirBundleManager) createBundleWithTypeAndResources(bundleType fhir4.BundleType, rawResources *[]json.RawMessage) fhir4.Bundle{
	fhirBundle:= fhirManager.createEmptyBundle(bundleType)
	fhirManager.AddRawResourcesToBundle(&fhirBundle, rawResources)
	// Finally it returns the FHIR Bundle with every resource contained in a BundleEntry with 'fullUrl'
	return fhirBundle
}

// Method createDefaultComposition creates FHIR.Composition with Author (urn:uuid:<uuid>) as mandatory, Type (11503-0), Status (preliminary), Date (timestamp in ISO format) but without ID
func (fhirManager *FhirBundleManager) createDefaultComposition(authorID, subjectID, categoryCodeLOINC *string) (fhir4.Composition, error){
	if authorID == nil { return fhir4.Composition{}, errors.New("author is mandatory when creating FHIR.Composition resource")}
	// not mandatory for now:
	// if subjectID == nil { return fhir4.Composition{}, errors.New("subject is mandatory when creating FHIR.Composition resource")}
	// if categoryCodeLOINC == nil { return fhir4.Composition{}, errors.New("category is mandatory when creating FHIR.Composition resource")}

	userSelected := false
	docTypeCodeLOINC := HL7ValueSetDocTypeMedicalRecords
	docTypeCodeSystem := HL7SystemValueSetDocTypeCodes

	compositionTypeCoding := &fhir4.Coding{
		System:       &docTypeCodeSystem,
		Code:         &docTypeCodeLOINC,
		UserSelected: &userSelected,
	}

	compositionTypeCodeable := fhir4.CodeableConcept{
		Coding:    []fhir4.Coding{*compositionTypeCoding},
	}

	// It creates FHIR.Composition without ID
	fhirComposition := fhir4.Composition{
		Type: compositionTypeCodeable,
		Status: fhir4.CompositionStatusPreliminary,
		Date:            time.Now().Format(time.RFC3339),
		Author:          nil,
	}

	if subjectID != nil {
		subjectURN := "urn:uuid:" + *subjectID
		fhirComposition.Subject = &fhir4.Reference{Reference: &subjectURN}
	}

	if categoryCodeLOINC != nil {
		loincCodeSystem := models.HL7CodeSystemLOINC
		compositionCategoryCoding := &fhir4.Coding{
			System:       &loincCodeSystem,
			Code:         categoryCodeLOINC,
			UserSelected: &userSelected,
		}

		compositionCategoryCodeable := fhir4.CodeableConcept{
			Coding:    []fhir4.Coding{*compositionCategoryCoding},
		}

		fhirComposition.Category = append(fhirComposition.Category, compositionCategoryCodeable)
	}

	return fhirComposition, nil
}

// Method CreateBundleDocument creates FHIR.Bundle with mandatory authorID
func (fhirManager *FhirBundleManager) CreateBundleDocument(rawResources *[]json.RawMessage, authorID, subjectID, categoryCodeLOINC, language *string) (fhir4.Bundle, error){
	fhirBundleDocument := fhirManager.createEmptyBundle(fhir4.BundleTypeDocument)

	fhirComposition, err := fhirManager.createDefaultComposition(authorID, subjectID, categoryCodeLOINC)
	if err != nil { return fhir4.Bundle{}, err}

	// It converts the FHIR resource to json.RawMessage type of BundleEntry.Resource
	fhirCompositionBytes, _ := json.Marshal(fhirComposition)
	fhirCompositionRaw, err := fhirManager.ResourceBytesToRawJson(&fhirCompositionBytes)
	if err != nil { return fhir4.Bundle{}, err}

	// First it adds the composition to the Bundle document
	fhirManager.AddRawResourceToBundle(&fhirBundleDocument, &fhirCompositionRaw)
	// Then adds the other raw resources to the Bundle document and returns
	fhirManager.AddRawResourcesToBundle(&fhirBundleDocument, rawResources)
	return fhirBundleDocument, nil
}

// TODO: Bundle resource fails not having eventCoding, eventUri, _eventUri (create pull request)
func (fhirManager *FhirBundleManager) createDefaultMessageHeaderFHIR(eventCodeUHC, messageID, authorID, entererID,
	responsibleID, senderID, receiverID, targetDeviceID, focusResourceID *string) fhir4.MessageHeader {

	messagingSystemName := MessagingSystemName
	messagingSoftwareName := MessagingSoftwareName
	messageHeader := fhir4.MessageHeader{
		Id: messageID, // The same as the UHC Message ID
		Source: 	fhir4.MessageHeaderSource{	// mandatory: Message source application
			Name:		&messagingSystemName,
			Software: 	&messagingSoftwareName,
			Endpoint: 	*messageID, // mandatory: Actual message source Address or id
		},
		Destination: []fhir4.MessageHeaderDestination{
			fhir4.MessageHeaderDestination{
				Endpoint:	*receiverID,		// Mandatory: actual destination Address or id
				Target:		&fhir4.Reference{
					Reference: targetDeviceID,	//Device reference: particular delivery destination within the destination
				},
				Receiver:	&fhir4.Reference{
					Reference: receiverID,		// Intended "real-world" recipient for the data
				},
			},
		},
		Sender: 	&fhir4.Reference{ Reference: senderID },		// Real world sender of the message
		Enterer: 	&fhir4.Reference{ Reference: entererID },		// PractitionerRole source of the data entry
		Author: 	&fhir4.Reference{ Reference: authorID },		// The source of the decision
		Responsible:&fhir4.Reference{ Reference: responsibleID },	// Final responsibility for event
		Focus:	[]fhir4.Reference{
			fhir4.Reference{
				Reference: focusResourceID,	// Reference to the resource ID with the actual content of the message
			},
		},
		Definition: nil, // defines a type of message that can be exchanged between systems: events, content and responses
	}

	return messageHeader
}

// 'authorID' is the source of the decision and 'entererID' is the PractitionerRole source of the data entry
func (fhirManager *FhirBundleManager) CreateDefaultFhirMessage(messageID, authorID, entererID,
	responsibleID, senderID, receiverID, targetDeviceID, focusResourceID *string) (fhir4.Bundle, error){

	fhirBundleMessage:=fhirManager.createBundleWithTypeAndResources(fhir4.BundleTypeMessage, nil)

	// TODO: createDefaultHeaderMessage with mandatory eventCoding
	fhirHeaderMessage := fhirManager.createDefaultMessageHeaderFHIR(nil, messageID, nil, nil, nil, nil, nil, nil, nil)

	// It converts the FHIR resource to json.RawMessage type of BundleEntry.Resource
	fhirHeaderMessageBytes, _ := json.Marshal(fhirHeaderMessage)
	fhirHeaderMessageRaw, err := fhirManager.ResourceBytesToRawJson(&fhirHeaderMessageBytes)
	if err != nil { return fhir4.Bundle{}, err}

	fhirManager.AddRawResourceToBundle(&fhirBundleMessage, &fhirHeaderMessageRaw)
	return fhirBundleMessage, nil
}

// 'authorID' is the source of the decision and 'entererID' is the PractitionerRole source of the data entry
func (fhirManager *FhirBundleManager) CreateFhirMessageWithRawResources(rawResources *[]json.RawMessage, messageID, authorID, entererID,
	responsibleID, senderID, receiverID, targetDeviceID, focusResourceID *string) (fhir4.Bundle, error){

	// It creates the FHIR Message with the MessageHeader
	fhirBundleMessage, err := fhirManager.CreateDefaultFhirMessage(messageID, authorID, entererID, responsibleID, senderID, receiverID, targetDeviceID, focusResourceID)
	if err != nil { return fhir4.Bundle{}, errors.New("error creating default FHIR Message")}

	// It adds every raw resource as BundleEntry in the FHIR Message and returns
	fhirManager.AddRawResourcesToBundle(&fhirBundleMessage, rawResources)
	return fhirBundleMessage, nil
}

// 'authorID' is the source of the decision and 'entererID' is the PractitionerRole source of the data entry
func (fhirManager *FhirBundleManager) CreateFhirMessageWithBundleDocument(fhirBundleDoc *fhir4.Bundle, messageID, authorID, entererID,
	responsibleID, senderID, receiverID, targetDeviceID, focusResourceID *string) (fhir4.Bundle, error){

	// It converts the FHIR Document to json.RawMessage type
	bundleDocumentBytes, _ := json.Marshal(fhirBundleDoc)
	bundleDocumentRaw, err := fhirManager.ResourceBytesToRawJson(&bundleDocumentBytes)
	if err != nil { return fhir4.Bundle{}, errors.New("error getting Bundle Document raw data")}

	// It creates the FHIR Message with the MessageHeader
	fhirBundleMessage, err := fhirManager.CreateDefaultFhirMessage(messageID, authorID, entererID, responsibleID, senderID, receiverID, targetDeviceID, focusResourceID)
	if err != nil { return fhir4.Bundle{}, errors.New("error creating default FHIR Message")}

	// It adds the Bundle Document as BundleEntry into the FHIR Message and returns
	fhirManager.AddRawResourceToBundle(&fhirBundleMessage, &bundleDocumentRaw)
	return fhirBundleMessage, nil
}

func (fhirManager *FhirBundleManager) ResourceBytesToRawJson(bytes *[]byte) (json.RawMessage, error) {
	if bytes == nil {return json.RawMessage{}, errors.New("no data to convert")}

	// It converts the bytes of any resource to json.RawMessage
	fhirResourceRaw := json.RawMessage{}
	err := fhirResourceRaw.UnmarshalJSON(*bytes)
	if err != nil {
		return json.RawMessage{}, errors.New("cannot get raw data from FHIR resource")
	}
	return fhirResourceRaw, nil
}

