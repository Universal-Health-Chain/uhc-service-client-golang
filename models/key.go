package models

import (
	"time"
)
const (
	KeyUsageEncryption 	= "ENCRYPTION"
	KeyUsageSigning    	= "SIGN"
	X25519KeyType 			= "X25519KeyAgreementKey2019"
	Ed25519KeyType 			= "Ed25519VerificationKey2018"
)

type Key struct {
	ID               string     `bson:"id,omitempty" json:"id,omitempty"`
	WalletKeyId      string     `bson:"walletKeyId,omitempty" json:"walletKeyId,omitempty"`
	Tag              string     `bson:"tag,omitempty" json:"tag,omitempty"`
	Capability       string     `bson:"capability,omitempty" json:"capability,omitempty"`	// TODO: Change to Purposes []string
	Type             string     `bson:"type,omitempty" json:"type,omitempty"`
	Usage            string     `bson:"usage,omitempty" json:"usage,omitempty"`
	PublicKeyBase64  string     `bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	PrivateKeyBase64 string     `bson:"privateKeyBase64,omitempty" json:"privateKeyBase64,omitempty"`
	CreatedAt        *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt        *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	ControllerDID    string     `bson:"controllerDid,omitempty" json:"controllerDid,omitempty"`	// "did:v1:uuid:" + uhcUserId
	PublicKeyDID     string     `bson:"publicKeyDid,omitempty" json:"publicKeyDid,omitempty"` 	// "did:v1:uuid:" + uhcUserId + "#" + Key.ID
	Expires          *time.Time `bson:"expires,omitempty" json:"expires,omitempty"`
	Revoked          *time.Time `bson:"revoked,omitempty" json:"revoked,omitempty"`
}
type KeyRetrievalRequest struct {
	AccessPassword  string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	EncryptionKeyID string `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
}
type KeyCreationRequest struct {
	AccessPassword string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	Tag            string `bson:"tag,omitempty" json:"tag,omitempty"`
}

type KeyCreationOrganizationRequest struct {
	OrganizationId string `bson:"organizationId,omitempty" json:"organizationId,omitempty"`
	AccessPassword *string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	Tag            string `bson:"tag,omitempty" json:"tag,omitempty"`
}

type KeyResponse struct {
	Code    int    `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64  `bson:"count,omitempty" json:"count,omitempty"`
	Message string `bson:"message,omitempty" json:"message,omitempty"`
	Data    []Key  `bson:"data,omitempty" json:"data,omitempty"`
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

// Standard expected properties: id (did#id), type, controller, publicKeyBase58 (https://w3c-ccg.github.io/security-vocab/)
type W3CPublicKeyExport struct { // controller is the blockchain's DID of the entity e.g. "did:v1:uuid:804c6ac3-ce3b-46ce-b134-17175d5bee74"
	IdWithDid       string     	`bson:"id,omitempty" json:"id,omitempty"`				// Identifier of this public key in the owner's blockchain DID document
	Controller		string		`bson:"controller,omitempty" json:"controller,omitempty"`	// didID already included in 'id'
	Type            string     	`bson:"type,omitempty" json:"type,omitempty"`			// "Ed25519VerificationKey2018""
	Expires			*time.Time	`bson:"expires,omitempty" json:"expires,omitempty"`
	Revoked			*time.Time	`bson:"revoked,omitempty" json:"revoked,omitempty"`
	PublicKeyBase64 string     	`bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	Context      	[]string		`bson:"@context,omitempty" json:"@context,omitempty"`		// "@context": ["https://w3id.org/security/v2"]
	PublicKeyBase58 string     		`bson:"publicKeyBase58,omitempty" json:"publicKeyBase58,omitempty"`	// standard
}
