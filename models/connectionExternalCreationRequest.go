/* Copyright 2021 Fundación UNID */
package models

type ConnectionExternalCreationRequest struct {
	Type                        string                     `json:"type" bson:"type"`
	Label                       string                     `json:"label,omitempty" bson:"label,omitempty"`
	Goal                        string                     `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode                    string                     `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	ExternalInvitationDetails   *ExternalInvitationDetails `json:"externalInvitationDetails,omitempty" bson:"externalInvitationDetails,omitempty"`
	InvitedUserId               string                     `json:"invitedUserId" bson:"invitedUserId"`
	InvitedUserEmail            string                     `json:"invitedUserEmail" bson:"invitedUserEmail"`
	EncryptionKeyOrganizationId string                     `json:"encryptionKeyOrganizationId" bson:"encryptionKeyOrganizationId"`
}
