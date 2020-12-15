package models

type Device struct {
	ID                  string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	OwnerOrganizationId string `bson:"ownerOrganizationId,omitempty" json:"ownerOrganizationId,omitempty"`
	Type                string `bson:"type,omitempty" json:"type,omitempty"`
}
