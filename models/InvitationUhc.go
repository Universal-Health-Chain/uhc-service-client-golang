/* Copyright 2021 Fundación UNID */
package models

import (
	"time"
)

type Invitation struct {
	ID        string        `json:"@id" bson:"@id"`
	Type      string        `json:"@type" bson:"@type"`
	Label     string        `json:"label,omitempty" bson:"label,omitempty"`
	Goal      string        `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode  string        `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	Service   []interface{} `json:"serviceClient" bson:"serviceClient"`
	Protocols []string      `json:"protocols" bson:"protocols"`
}

type InvitationUHC struct {
	ID                        string                     `json:"id" bson:"id"`
	ShortId                   string                     `json:"shortId" bson:"shortId"`
	Type                      string                     `json:"type" bson:"type"`
	Label                     string                     `json:"label,omitempty" bson:"label,omitempty"`
	Goal                      string                     `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode                  string                     `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	Protocols                 []string                   `json:"protocols" bson:"protocols"`
	Password                  string                     `json:"password" bson:"password"`
	Status                    string                     `json:"status" bson:"status"`
	InitiatorUserId           string                     `json:"initiatorUserId,omitempty" bson:"initiatorUserId,omitempty"`
	InvitedUserId             string                     `json:"invitedUserId,omitempty" bson:"invitedUserId,omitempty"`
	CreatedAt                 *time.Time                 `json:"createdAt" bson:"createdAt"`
	UpdatedAt                 *time.Time                 `json:"updatedAt" bson:"updatedAt"`
	EncryptionRequirements    EncryptionRequirements     `json:"encryptionRequirements" bson:"encryptionRequirements"`
	ExternalInvitationDetails *ExternalInvitationDetails `json:"externalInvitationDetails,omitempty" bson:"externalInvitationDetails,omitempty"`
	ReadStatus          	  string                     `json:"readStatus,omitempty" bson:"readStatus,omitempty"`
}
type ExternalInvitationDetails struct {
	ExternalSenderUserDetails *ExternalSenderUserDetails `json:"externalSenderUserDetails,omitempty" bson:"externalSenderUserDetails,omitempty"`
	OrganizationId   string                     `json:"organizationId,omitempty" bson:"organizationId,omitempty"`
}


type InvitationCreationRequest struct {
	Type                     string  `json:"type" bson:"type"`
	Label                    string  `json:"label,omitempty" bson:"label,omitempty"`
	Goal                     string  `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode                 string  `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	Password                 string  `json:"password" bson:"password"`
	InitiatorUserId          string  `json:"initiatorUserId" bson:"initiatorUserId"`
	InvitedUserId            string  `json:"invitedUserId" bson:"invitedUserId"`
	InitiatorPublicKey       string  `bson:"initiatorPublicKey,omitempty" json:"initiatorPublicKey,omitempty"`
	InitiatorEncryptionKeyId *string `json:"initiatorEncryptionKeyId" bson:"initiatorEncryptionKeyId"`
}

type InvitationAcceptationRequest struct {
	InvitationUhcId        string  `json:"invitationUhcId" bson:"invitationUhcId"`
	Password               string  `json:"password" bson:"password"`
	InvitedPublicKey       string  `bson:"invitedPublicKey,omitempty" json:"invitedPublicKey,omitempty"`
	InvitedEncryptionKeyId *string `json:"invitedEncryptionKeyId" bson:"invitedEncryptionKeyId"`
}

type ConnectionCreationImplicitRequest struct {
	Type                             string `json:"type" bson:"type"`
	Label                            string `json:"label,omitempty" bson:"label,omitempty"`
	Goal                             string `json:"goal,omitempty" bson:"goal,omitempty"`
	GoalCode                         string `json:"goal-code,omitempty" bson:"goal-code,omitempty"`
	ImplicitInitiatorUserId          string `json:"implicitInitiatorUserId" bson:"implicitInitiatorUserId"`
	ImplicitInvitationTokenInitiator string `json:"implicitInvitationTokenInitiator" bson:"implicitInvitationTokenInitiator"`
}

type InvitationUHCResponse struct {
	Code    int             `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64           `bson:"count,omitempty" json:"count,omitempty"`
	Message string          `bson:"message,omitempty" json:"message,omitempty"`
	Data    []InvitationUHC `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token           `bson:"token,omitempty" json:"token,omitempty"`
}
