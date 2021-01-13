/* Copyright 2021 Fundación UNID */
package models

type ExternalBase64MessageCreationRequest struct {
	ExternalMessageDirectives ExternalMessageDirectives `json:"externalDirectives" bson:"externalDirectives"`
	Base64Message             string                    `json:"base64Message,omitempty" bson:"base64Message,omitempty"`
	Type                      string                    `json:"type,omitempty" bson:"type,omitempty"`
	FileType                  *string                   `json:"FileType,omitempty" bson:"FileType,omitempty"`
}
