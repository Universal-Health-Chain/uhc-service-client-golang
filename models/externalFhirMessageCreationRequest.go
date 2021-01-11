/* Copyright 2021 Fundación UNID */
package models

import fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"


type ExternalFhirMessageCreationRequest struct {
	ExternalMessageDirectives ExternalMessageDirectives `json:"externalDirectives" bson:"externalDirectives"`
	FhirMessage        fhir4.Bundle              `json:"fhirMessage,omitempty" bson:"fhirMessage,omitempty"`
}

type ExternalMessageDirectives struct {
	ToEmail               string  `json:"toEmail,omitempty" bson:"toEmail,omitempty"`
	FromOrganizationEmail *string `json:"fromOrganizationEmail,omitempty" bson:"fromOrganizationEmail,omitempty"`
	ToUserId              *string `json:"toUserId,omitempty" bson:"toUserId,omitempty"`
}

