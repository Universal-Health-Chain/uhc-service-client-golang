package models

const (
	WalletKeyOwnerTypeDevice = "DEVICE"
	WalletKeyOwnerTypeUSER = "USER"
)

type WalletKey struct {
	AccessPassword string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	OwnerId        string `bson:"ownerId,omitempty" json:"ownerId,omitempty"`
	OwnerType      string `bson:"ownerType,omitempty" json:"ownerType,omitempty"`
	Type           string `bson:"type,omitempty" json:"type,omitempty"`
}
