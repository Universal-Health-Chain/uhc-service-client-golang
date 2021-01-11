/* Copyright 2021 Fundación UNID */
package models

import (
	fhir4 "github.com/samply/golang-fhir-models/fhir-models/fhir"
	"time"
)

type OrganizationUHCAccess struct {
	ID                              string                   `bson:"id,omitempty" json:"id,omitempty"`
	OrganizationUhcId               string                   `bson:"organizationUhcId,omitempty" json:"organizationUhcId,omitempty"`
	ActiveEncryptionKeyID           *string                  `bson:"activeEncryptionKeyID,omitempty" json:"activeEncryptionKeyID,omitempty"`
	ActiveSigningKeyID              *string                  `bson:"activeSigningKeyID,omitempty" json:"activeSigningKeyID,omitempty"`
	ActiveOrganizationAccessTokenId *string                  `bson:"activeOrganizationAccessTokenId,omitempty" json:"activeOrganizationAccessTokenId,omitempty"`
	ApplicationsLicenses            *[]ApplicationLicense    `bson:"ApplicationsLicenses,omitempty" json:"applications,omitempty"`
	ApplicationsPermissions         *[]ApplicationPermission `bson:"applicationsPermissions,omitempty" json:"applicationsPermissions,omitempty"`
}

type ApplicationLicense struct {
	AppName  string    `bson:"id,omitempty" json:"id,omitempty"`
	AppKey   string    `bson:"key,omitempty" json:"key,omitempty"`
	Licenses []License `bson:"licenses,omitempty" json:"licenses,omitempty"`
}

type ApplicationPermission struct {
	ServiceName string     `bson:"serviceName,omitempty" json:"serviceName,omitempty"`
	ServiceRole string     `bson:"serviceRole,omitempty" json:"serviceRole,omitempty"`
	CreatedAt   *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt   *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}

type License struct {
	LicenseID string       `bson:"id,omitempty" json:"id,omitempty"`
	Period    fhir4.Period `bson:"period,omitempty" json:"period,omitempty"`
	Type      string       `bson:"type,omitempty" json:"type,omitempty"`
	CreatedAt *time.Time   `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt *time.Time   `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}
