package models

import "time"

const (
	WalletKeyOwnerTypeDevice = "DEVICE"
	WalletKeyOwnerTypeUSER   = "USER"
)

type WalletKey struct {		// TODO: It should be 'Wallet' or 'WalletEntry' but not 'WalletKey'
	AccessPassword        string     `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	ID                    string     `bson:"id,omitempty" json:"id,omitempty"`
	BlockchainDID			string		`bson:"did,omitempty" json:"did,omitempty"`
	OwnerId               string     `bson:"ownerId,omitempty" json:"ownerId,omitempty"`
	OwnerType             string     `bson:"ownerType,omitempty" json:"ownerType,omitempty"`
	Type                  string     `bson:"type,omitempty" json:"type,omitempty"`
	CreatedAt             *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt             *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	ActiveEncryptionKeyId *string    `bson:"activeEncryptionKey,omitempty" json:"activeEncryptionKey,omitempty"`
	ActiveSigningKeyId    *string    `bson:"activeSingingKey,omitempty" json:"activeSingingKey,omitempty"`
}


type WalletKeyResponse struct {
	Code    int          `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64        `bson:"count,omitempty" json:"count,omitempty"`
	Message string       `bson:"message,omitempty" json:"message,omitempty"`
	Data    []WalletKey `bson:"data,omitempty" json:"data,omitempty"`
}