package models

import (
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
)

type OrganizationUHC struct {
	ID                   string                           `bson:"id,omitempty" json:"id,omitempty"`
	ActiveCredentialID   string                           `bson:"activeCredential,omitempty" json:"activeCredential,omitempty"`
	ApplicationsLicenses *[]ApplicationLicense            `bson:"applications,omitempty" json:"applications,omitempty"`
	FhirOrganization     *fhir4.Organization              `bson:"fhir,omitempty" json:"fhir,omitempty"`
	UhcPublicExtensions  *OrganizationPublicUHCExtensions `bson:"uhcPublicExtensions,omitempty" json:"uhcPublicExtensions,omitempty"` //dlt: no
}

type ApplicationLicense struct {
	AppName  string    `bson:"id,omitempty" json:"id,omitempty"`
	AppKey   string    `bson:"key,omitempty" json:"key,omitempty"`
	Licenses []License `bson:"licenses,omitempty" json:"licenses,omitempty"`
}

type License struct {
	LicenseID string       `bson:"id,omitempty" json:"id,omitempty"`
	Period    fhir4.Period `bson:"period,omitempty" json:"period,omitempty"`
	Type      string       `bson:"type,omitempty" json:"type,omitempty"`
}

type OrganizationPublicUHCExtensions struct {
	AppId                       string      `bson:"appId,omitempty" json:"appId,omitempty"`
	DescriptionI18n             *[]I18nText `bson:"description~i18n,omitempty" json:"description~i18n,omitempty"`
	Tags                        *[]string   `bson:"tags,omitempty" json:"tags,omitempty"`
	LogoUrl                     string      `bson:"logoUrl,omitempty" json:"logoUrl,omitempty"`
	OrganizationImageDocumentId string      `bson:"organizationImageDocumentId,omitempty" json:"prganizationImageDocumentId,omitempty"`
	OrganizationId              string      `bson:"organizationId,omitempty" json:"organizationId,omitempty"`
	ActiveTermsAndConditionsId  string      `bson:"termsAndConditionsId,omitempty" json:"termsAndConditionsId,omitempty"`
}

type I18nText struct {
	Language string `bson:"language,omitempty" json:"language,omitempty"`
	Text     string `bson:"text,omitempty" json:"text,omitempty"`
}

type OrganizationUHCResponse struct {
	Code    int               `bson:"code,omitempty" json:"code,omitempty"`
	Message string            `bson:"message,omitempty" json:"message,omitempty"`
	Data    []OrganizationUHC `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token             `bson:"token,omitempty" json:"token,omitempty"`
}