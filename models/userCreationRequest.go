/* Copyright 2021 Fundación UNID */
package models

type UserExternalCreationRequest struct {
	Email                      string `bson:"email,omitempty" json:"email,omitempty"`
	PhoneNumber                string `bson:"phoneNumber,omitempty" json:"phoneNumber,omitempty"`
	IdentificationDocumentCode string `bson:"identificationDocumentCode,omitempty" json:"identificationDocumentCode,omitempty"`
	IdentificationDocumentType string `bson:"identificationDocumentType,omitempty" json:"identificationDocumentType,omitempty"`
}