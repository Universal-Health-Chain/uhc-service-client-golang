package models

type ConnectionExternalCreationRequest struct {
	Type                        string `json:"type" bson:"type"`
	Label                       string `json:"label,omitempty" bson:"label,omitempty"`
	Goal                        string `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode                    string `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	OrganizationCreatorId       string `json:"organizationCreatorId" bson:"organizationCreatorId"`
	InvitedUserId               string `json:"invitedUserId" bson:"invitedUserId"`
	EncryptionKeyOrganizationId string `json:"encryptionKeyOrganizationId" bson:"encryptionKeyOrganizationId"`
}
