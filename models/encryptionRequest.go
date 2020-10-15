package models

type EncryptionRequest struct {
	Payload                  string `bson:"payload,omitempty" json:"payload,omitempty"`
	EncryptionKeyId          string `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
	AccessPassword           string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	RecipientPublicKeyBase64 string `bson:"recipientPublicKeyBase64,omitempty" json:"recipientPublicKeyBase64,omitempty"`
}

type DecryptionRequest struct {
	Payload               string `bson:"payload,omitempty" json:"payload,omitempty"`
	EncryptionKeyId       string `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
	AccessPassword        string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	SenderPublicKeyBase64 string `bson:"senderPublicKeyBase64,omitempty" json:"senderPublicKeyBase64,omitempty"`
}

type EncryptedResult struct {
	EncryptedMessageBase64 string `bson:"encryptedMessageBase64,omitempty" json:"encryptedMessageBase64,omitempty"`
}

type DecryptedResult struct {
	DecryptedMessage string `bson:"decryptedMessage,omitempty" json:"decryptedMessage,omitempty"`
}

type EncryptedResultResponse struct {
	Code    int               `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64             `bson:"count,omitempty" json:"count,omitempty"`
	Message string            `bson:"message,omitempty" json:"message,omitempty"`
	Data    []EncryptedResult `bson:"data,omitempty" json:"data,omitempty"`
}

type DecryptedResultResponse struct {
	Code    int               `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64             `bson:"count,omitempty" json:"count,omitempty"`
	Message string            `bson:"message,omitempty" json:"message,omitempty"`
	Data    []DecryptedResult `bson:"data,omitempty" json:"data,omitempty"`
}
