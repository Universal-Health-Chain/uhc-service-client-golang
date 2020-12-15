package models

import (
	"time"
)

const (
	EncryptionKeyTypeEncryption = "ENCRYPTION"
	EncryptionKeyTypeSigning = "SIGN"
)

type EncryptionKey struct {
	ID               string     `bson:"id,omitempty" json:"id,omitempty"`
	WalletKeyId      string     `bson:"walletKeyId,omitempty" json:"walletKeyId,omitempty"`
	Tag              string     `bson:"tag,omitempty" json:"tag,omitempty"`
	Type             string     `bson:"type,omitempty" json:"type,omitempty"`
	PublicKeyBase64  string     `bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	PrivateKeyBase64 string     `bson:"privateKeyBase64,omitempty" json:"privateKeyBase64,omitempty"`
	CreatedAt        *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt        *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}

type EncryptionKeyRetrievalRequest struct {
	AccessPassword  string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	EncryptionKeyID string `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
}

type EncryptionKeyCreationRequest struct {
	AccessPassword string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	Tag            string `bson:"tag,omitempty" json:"tag,omitempty"`
}

type EncryptionKeyResponse struct {
	Code    int             `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64           `bson:"count,omitempty" json:"count,omitempty"`
	Message string          `bson:"message,omitempty" json:"message,omitempty"`
	Data    []EncryptionKey `bson:"data,omitempty" json:"data,omitempty"`
}
type PublicInfoFromActiveKey struct {
	ID              string     `bson:"id,omitempty" json:"id,omitempty"`
	Tag             string     `bson:"tag,omitempty" json:"tag,omitempty"`
	OwnerUserId     string     `bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
	PublicKeyBase64 string     `bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	CreatedAt       *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt       *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}
type PublicInfoFromKeyResponse struct {
	Code    int                       `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64                     `bson:"count,omitempty" json:"count,omitempty"`
	Message string                    `bson:"message,omitempty" json:"message,omitempty"`
	Data    []PublicInfoFromActiveKey `bson:"data,omitempty" json:"data,omitempty"`
}
