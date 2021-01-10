package commonManagers

import (
	"encoding/json"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/google/uuid"
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
	"time"
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

type FhirManager struct {}

func (fhirManager *FhirManager) createEmptyBundle(bundleType fhir4.BundleType) fhir4.Bundle{
	randomUuid, _ := uuid.NewRandom()
	idStr := randomUuid.String()

	fhirBundle := &fhir4.Bundle{
		Id:            &idStr,
		Type:          bundleType,
	}
	return *fhirBundle
}

func (fhirManager *FhirManager) CreateBundleWithType(bundleType fhir4.BundleType) fhir4.Bundle{
	fhirBundle:= fhirManager.createEmptyBundle(bundleType)
	return fhirBundle

}

// Method CreateDefaultComposition creates FHIR.Composition with Author (urn:uuid:<uuid>) as mandatory, Type (11503-0), Status (preliminary), Date (timestamp in ISO format) but without ID
func (fhirManager *FhirManager) CreateDefaultComposition(authorID, subjectID, categoryCodeLOINC *string) (fhir4.Composition, error){
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

// TODO: It does not add entry[].fullUrl
func (fhirManager *FhirManager) AddRawResourceToBundleFHIR(fhirBundle *fhir4.Bundle, resourceRaw *json.RawMessage) error{
	// It prepares and inserts the new Bundle.Entry
	newBundleEntry := fhir4.BundleEntry{
		// TODO: fullUrl: "urn:uhc:...:uuid"
		Resource: *resourceRaw,
	}
	fhirBundle.Entry = append(fhirBundle.Entry, newBundleEntry)
	return nil
}

// Method CreateBundleDocument creates FHIR.Bundle with mandatory authorID
func (fhirManager *FhirManager) CreateBundleDocument(authorID, subjectID, categoryCodeLOINC, language *string) (fhir4.Bundle, error){
	// It creates the FHIR.Composition with mandatory authorID or error
	fhirComposition, err := fhirManager.CreateDefaultComposition(authorID, subjectID, categoryCodeLOINC)
	if err != nil { return fhir4.Bundle{}, err}

	fhirCompositionBytes, _ := json.Marshal(fhirComposition)
	fhirCompositionRaw, err := fhirManager.ResourceBytesToRawJson(&fhirCompositionBytes)

	fhirBundleDocument :=fhirManager.CreateBundleWithType(fhir4.BundleTypeDocument)
	err = fhirManager.AddRawResourceToBundleFHIR(&fhirBundleDocument, &fhirCompositionRaw)
	return fhirBundleDocument, nil
}

func (fhirManager *FhirManager) CreateFhirMessage() (fhir4.Bundle, error){
	// TODO: CreateDefaultHeaderMessage with mandatory eventCoding and sourceMessageID, URL or URN
	// fhirHeaderMessage, err := fhirManager.CreateDefaultHeaderMessage(authorID, subjectID, categoryCodeLOINC)
	// if err != nil { return fhir4.Bundle{}, err}

	fhirBundleMessage:=fhirManager.CreateBundleWithType(fhir4.BundleTypeMessage)
	// AddResourcesToBundleFHIR
	return fhirBundleMessage, nil
}

func (fhirManager *FhirManager) ResourceBytesToRawJson(bytes *[]byte) (json.RawMessage, error) {
	if bytes == nil {return json.RawMessage{}, errors.New("no data to convert")}

	// It converts the bytes of any resource to json.RawMessage
	fhirResourceRaw := json.RawMessage{}
	err := fhirResourceRaw.UnmarshalJSON(*bytes)
	if err != nil {
		return json.RawMessage{}, errors.New("cannot get raw data from FHIR resource")
	}
	return fhirResourceRaw, nil
}
