/* Copyright 2021 Fundación UNID */
package models
type SharedKey struct {
	EncryptionKeyId     	*string   `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
	OtherPartPublicKey     string   `bson:"otherPartPublicKey,omitempty" json:"otherPartPublicKey,omitempty"`
	SharedKey        string     `bson:"sharedKey,omitempty" json:"sharedKey,omitempty"`

}
type SharedKeyResponse struct {
	Code    int             `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64           `bson:"count,omitempty" json:"count,omitempty"`
	Message string          `bson:"message,omitempty" json:"message,omitempty"`

	Data    []SharedKey 	`bson:"data,omitempty" json:"data,omitempty"`
}
type SharedKeyCreationRequest struct {
	EncryptionKeyId     	*string   `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
	OtherPartPublicKey     string   `bson:"otherPartPublicKey,omitempty" json:"otherPartPublicKey,omitempty"`
	AccessPassword        string   `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`

}
