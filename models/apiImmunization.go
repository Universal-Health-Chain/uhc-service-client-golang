/* Copyright 2021 Fundación UNID */
package models

import (
	// "github.com/dgrijalva/jwt-go"
	//  "github.com/square/go-jose/v3/jwt"
	"net/http"
)

type ImmunizationApiParams struct {
	// UHC specific
	ConnectionUHC 			string	// UHC private connection e.g. http://api.unid.es/v1/connection/987
	RecipientMessageUHC		string

	// Immunization Terminology Bindings
	VaccineCode				string	// system|code
	ImmunizationSite		string
	ImmunizationRoute		string

	// Immunization Search Params
	OccurrenceDate			string	// Vaccination (non)-Administration Date
	Identifier				string	// Cross border identifier (not internal ID)
	Location				string	// The service delivery location or facility in which the vaccine was / was to be administered
	LotNumber				string	// Vaccine lot number.
	Manufacturer			string	// Vaccine Manufacturer Organization Reference URI
	Patient					string	// Who/what is the patient for the resource
	Performer				string	// The practitioner or organization who played a role in the vaccination
	Reaction 				string	// Observation with details on reaction
	ReactionDate 			string	// Both for immunization and for allergies and intolerances
	ReasonCode             	string	// Reason why the vaccine was administered
	ReasonReference			string	// Resource about why immunization occurred
	Series					string	// The series being followed by the provider
	StatusHL7             	string	// Immunization event status
	StatusReason			string	// Not done reason code
	TargetDiseases			string	// Target diseases.

	// Added Params
	SerieDosesRecommended   string	// Recommended number of doses for immunity.
	SerieDoseNumber			string	// Dose number within series e.g.: 1
	ValueQuantity			string	// Amount administered as quantity|unitcode e.g.: 1|mL
}

// Method GetImmunizationApiTags returns the valid params to be used
func (apiImmunization *ImmunizationApiParams) GetImmunizationApiTags() ImmunizationApiParams{
	immunizationApiTags := &ImmunizationApiParams{
		ConnectionUHC:         	UhcApiConnection, // ID of an existing connection
	}
	return *immunizationApiTags
}

// Method GetImmunizationFormByHttpRequest returns a BaseImmunization created with the params received
func (apiImmunization *ImmunizationApiParams) GetImmunizationFormByHttpRequest(r *http.Request) {
	// TODO:
	// immunizationApiParams := &ImmunizationApiParams{}
	// immunizationHeaders := immunizationApiParams.GetImmunizationApiTags()
}

