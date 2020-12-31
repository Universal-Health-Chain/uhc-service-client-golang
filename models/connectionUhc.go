package models

import (
	"time"
)

type ConnectionUHC struct {
	ID                        string                   `json:"id" bson:"id"`
	InvitationUhcId           string                   `json:"invitationUhcId,omitempty" bson:"invitationUhcID,omitempty"`
	InitiatorUserId           string                   `json:"initiatorUserId,omitempty" bson:"initiatorUserId,omitempty"`
	InitiatorOrganizationId   string                   `json:"initiatorOrganizationId,omitempty" bson:"initiatorOrganizationId,omitempty"`
	InvitedUserId             string                   `json:"invitedUserId,omitempty" bson:"invitedUserId,omitempty"`
	EncryptionRequirements    EncryptionRequirements   `json:"encryptionRequirements" bson:"encryptionRequirements"`
	ActivePermissions         *[]PermissionsUHC        `json:"activePermissions" bson:"activePermissions"`
	PendingPermissionsRequest *[]PermissionsRequestUHC `json:"requestedPendingPermissions" bson:"requestedPendingPermissions"`
	CreatedAt                 *time.Time               `json:"createdAt" bson:"createdAt"`
	UpdatedAt                 *time.Time               `json:"updatedAt" bson:"updatedAt"`
	Status                    string                   `json:"status" bson:"status"`
}

type EncryptionRequirements struct {
	InitiatorPublicKey      string  `bson:"initiatorPublicKey,omitempty" json:"initiatorPublicKey,omitempty"`
	InvitedPublicKey        string  `bson:"invitedPublicKey,omitempty" json:"invitedPublicKey,omitempty"`
	InitiatorEncyptionKeyId *string `json:"initiatorEncyptionKeyId" bson:"initiatorEncyptionKeyId"`
	InvitedEncyptionKeyId   *string `json:"invitedEncyptionKeyId" bson:"invitedEncyptionKeyId"`
}

type PermissionsUHC struct {
	AccessCode string `json:"accessCode" bson:"accessCode"`
	Active     *bool  `json:"active" bson:"active"`
	Goal       string `json:"goal" bson:"goal"`
}

type PermissionsRequestUHC struct {
	ID                   string            `json:"id" bson:"id"`
	ConnectionId         string            `json:"connectionId" bson:"connectionId"`
	PermissionsRequested *[]PermissionsUHC `json:"permissionsRequested" bson:"permissionsRequested"`
	ActiveUntil          *time.Time        `json:"activeUntil" bson:"activeUntil"`
	Goal                 string            `json:"goal" bson:"goal"`
	Status               string            `json:"status" bson:"status"`
}

type PermissionUHCAccessRequest struct {
	Permissions []PermissionsUHC `json:"permissions" bson:"permissions"`
	Until       time.Time        `json:"until" bson:"until"`
}

type ConnectionUHCResponse struct {
	Code    int             `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64           `bson:"count,omitempty" json:"count,omitempty"`
	Message string          `bson:"message,omitempty" json:"message,omitempty"`
	Data    []ConnectionUHC `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token           `bson:"token,omitempty" json:"token,omitempty"`
}
