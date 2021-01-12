/* Copyright 2021 Fundación UNID */
package models

import fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"

type ExternalFhirMessageCreationRequest struct {
	ExternalMessageDirectives ExternalMessageDirectives `json:"externalDirectives" bson:"externalDirectives"`
	FhirMessage               fhir4.Bundle              `json:"fhirMessage,omitempty" bson:"fhirMessage,omitempty"`
}

type ExternalMessageDirectives struct {
	ToEmail  string  `json:"toEmail,omitempty" bson:"toEmail,omitempty"`
	ToUserId *string `json:"toUserId,omitempty" bson:"toUserId,omitempty"`
	ExternalSenderUserDetails *ExternalSenderUserDetails `json:"externalSenderUserDetails,omitempty" bson:"externalSenderUserDetails,omitempty"`
}

type ExternalSenderUserDetails struct {
	Email               string  `json:"toEmail,omitempty" bson:"toEmail,omitempty"`
	FirstName           string  `json:"fromOrganizationEmail,omitempty" bson:"fromOrganizationEmail,omitempty"`
	LastName            string  `json:"toUserId,omitempty" bson:"toUserId,omitempty"`
	TitleInOrganization *string `json:"toUserId,omitempty" bson:"toUserId,omitempty"`
}
