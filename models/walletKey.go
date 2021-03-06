/* Copyright 2021 Fundación UNID */
package models

import "time"

const (
	WalletKeyOwnerTypeDevice = "DEVICE"
	WalletKeyOwnerTypeUSER   = "USER"
)

type WalletKey struct {
	AccessPassword                    string     `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	ID                                string     `bson:"id,omitempty" json:"id,omitempty"`
	ControllerDID                     string     `bson:"did,omitempty" json:"did,omitempty"`
	RecoverCode                       string     `bson:"recoverCode,omitempty" json:"recoverCode,omitempty"`
	OwnerId                           string     `bson:"ownerId,omitempty" json:"ownerId,omitempty"`
	OwnerType                         string     `bson:"ownerType,omitempty" json:"ownerType,omitempty"`
	Type                              string     `bson:"type,omitempty" json:"type,omitempty"`
	CreatedAt                         *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt                         *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	ActiveEncryptionKeyId             *string    `bson:"activeEncryptionKey,omitempty" json:"activeEncryptionKey,omitempty"`
	ActiveSigningKeyId                *string    `bson:"activeSingingKey,omitempty" json:"activeSingingKey,omitempty"`
	MultifactorAuthCode               *string    `bson:"multifactorAuthCode,omitempty" json:"multifactorAuthCode,omitempty"`
	MultifactorAuthCodeGenerationDate *time.Time `bson:"multifactorAuthCodeGenerationDate,omitempty" json:"multifactorAuthCodeGenerationDate,omitempty"`
}

type WalletKeyResponse struct {
	Code    int         `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64       `bson:"count,omitempty" json:"count,omitempty"`
	Message string      `bson:"message,omitempty" json:"message,omitempty"`
	Data    []WalletKey `bson:"data,omitempty" json:"data,omitempty"`
}

type WalletPasswordChangeRequest struct {
	NewPassword string `bson:"newPassword,omitempty" json:"newPassword,omitempty"`
	OwnerUserId string `bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
}
