package models

import (
	"time"
)

type MessageUHC struct {
	ID                  string      `json:"id" bson:"id"`
	ConnectionUhcId     string      `json:"connectionUhcId" bson:"connectionUhcId"`
	Thread              string      `json:"thread" bson:"thread"`
	RespondsToMessageId string      `json:"respondsToMessageId" bson:"respondsToMessageId"`
	Type                string      `json:"type" bson:"type"`
	Label               string      `json:"label" bson:"label"`
	FromUserId          string      `json:"fromUserId" bson:"fromUserId"`
	ToUserId            string      `json:"toUserId" bson:"toUserId"`
	JWMPayload          *JWMPayload `json:"jwmPayload" bson:"jwmPayload"`
	UHCPayload          *UHCPayload `json:"uhcPayload" bson:"uhcPayload"`
	CreatedAt           *time.Time  `json:"createdAt" bson:"createdAt"`
	Status              string      `json:"status" bson:"status"`
}

type JWMPayload struct {
	Protected  string `json:"protected" bson:"protected"`
	IV         string `json:"iv" bson:"iv"`
	Ciphertext string `json:"ciphertext" bson:"ciphertext"`
	Tag        string `json:"tag" bson:"tag"`
}

type UHCPayload struct {
	PayloadBase64    string `json:"payloadBase64" bson:"payloadBase64"`
	EncryptedPayload bool   `json:"encryptedPayload" bson:"encryptedPayload"`
}

type MessageUHCResponse struct {
	Code    int          `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64        `bson:"count,omitempty" json:"count,omitempty"`
	Message string       `bson:"message,omitempty" json:"message,omitempty"`
	Data    []MessageUHC `bson:"data,omitempty" json:"data,omitempty"`
	Token   Token        `bson:"token,omitempty" json:"token,omitempty"`
}