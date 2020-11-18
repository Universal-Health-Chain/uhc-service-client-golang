package models

import (
	"time"
)

type EncryptionKey struct {
	ID               string     `bson:"id,omitempty" json:"id,omitempty"`
	OwnerUserId      string     `bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
	Tag              string     `bson:"tag,omitempty" json:"tag,omitempty"`
	AccessPassword   string     `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
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

