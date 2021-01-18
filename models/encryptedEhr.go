package models

type EncryptedEhr struct {
	ID                     string   `bson:"id,omitempty" json:"id,omitempty"`
	Type                   string   `bson:"type,omitempty" json:"type,omitempty"`
	UhcUserId              string   `json:"uhcUserId,omitempty" bson:"uhcUserId,omitempty"`
	KeyId                  string   `json:"keyId,omitempty" bson:"keyId,omitempty"`
	EncryptedPayloadBase64 string   `bson:"encryptedPayloadBase64,omitempty" json:"encryptedPayloadBase64,omitempty"`
	Codes                  []string `bson:"codes,omitempty" json:"codes,omitempty"`
	UhcCodeTags            []string `bson:"uhcCodeTags,omitempty" json:"uhcCodeTags,omitempty"`
}

type EncryptedEhrResponse struct {
	Code    int               `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64             `bson:"count,omitempty" json:"count,omitempty"`
	Message string            `bson:"message,omitempty" json:"message,omitempty"`
	Data    []EncryptedEhr `bson:"data,omitempty" json:"data,omitempty"`
}
