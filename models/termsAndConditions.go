package models

import "time"

type TermsAndConditionsResponse struct {
	Code    int                  `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64                `bson:"count,omitempty" json:"count,omitempty"`
	Message string               `bson:"message,omitempty" json:"message,omitempty"`
	Data    []TermsAndConditions `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token                `bson:"token,omitempty" json:"token,omitempty"`
}

type TermsAndConditions struct {
	Text          string    `bson:"text,omitempty" json:"text,omitempty"`
	CreationDate  time.Time `bson:"creationDate,omitempty" json:"creationDate,omitempty"`
	Version       string    `bson:"version,omitempty" json:"version,omitempty"`
	ID            string    `bson:"id,omitempty" json:"id,omitempty"`
	ActiveVersion bool      `bson:"activeVersion,omitempty" json:"activeVersion,omitempty"`
	Type          string    `bson:"type,omitempty" json:"type,omitempty"`
}