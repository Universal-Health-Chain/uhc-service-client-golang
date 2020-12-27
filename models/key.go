package models

import (
	"time"
)

const (
	EncryptionKeyTypeEncryption = "ENCRYPTION"
	EncryptionKeyTypeSigning    = "SIGN"
)

// NOTE: W3C's Security Vocabulary terms are used - https://w3c-ccg.github.io/security-vocab/

// TODO: should be used 'KeyPairStorage' instead of 'Key'
type KeyPairStorage struct {		// Only private 'purposes' data or public 'revoked' data can be updated
	ID				string			`bson:"id,omitempty" json:"id,omitempty"`	// UHC key pair UUID
	Meta			KeyPairMeta		`bson:",inline"`
	PublicKeyInfo	PublicKeyInfo	`bson:",inline"`
	PrivateKeyInfo	PrivateKeyInfo	`bson:",inline"`
}

type KeyPairMeta struct {	// Only 'capabilities' or 'revoked' can be updated
	Created		*time.Time	`bson:"created,omitempty" json:"created,omitempty"`
	Updated 	*time.Time	`bson:"updated,omitempty" json:"updated,omitempty"`	// Not included in W3C's security vocabulary
	Tag			string     	`bson:"tag,omitempty" json:"tag,omitempty"`			// Not included in W3C's security vocabulary
}

type PrivateKeyInfo struct {	// Terms not included in W3C's security vocabulary
	WalletId      	string     	`bson:"walletId,omitempty" json:"walletId,omitempty"`	// Wallet's identifier of this public key
	Purposes     	[]string	`bson:"purposes,omitempty" json:"purposes,omitempty"`	// e.g. ["authentication","recovery","assertionMethod"]
	PrivateKeyBase64 string     `bson:"privateKeyBase64,omitempty" json:"privateKeyBase64,omitempty"`
	// Passphrase 	string 		// "passphrase" to encrypt the generated private key at the DID document (not for public blockchain)",
}

// UHC expected properties: id (did#id), type, publicKeyBase64 (controller is included in the 'id')
type PublicKeyInfo struct {		// Using W3C's terms: https://w3c-ccg.github.io/security-vocab/#Ed25519VerificationKey2018, the public owner is included in 'id'
	IdWithDid       string     	`bson:"id,omitempty" json:"id,omitempty"`		// Identifier of this public key in the owner's blockchain DID document
	Type            string     	`bson:"type,omitempty" json:"type,omitempty"`	// "Ed25519VerificationKey2018""
	Expires			*time.Time	`bson:"expires,omitempty" json:"expires,omitempty"`
	Revoked			*time.Time	`bson:"revoked,omitempty" json:"revoked,omitempty"`
	PublicKeyBase64 string     	`bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
}

type PublicInfoByActiveKey struct {	// Revealing both owner's universal identifier in UHC and blockchain owner's DID document
	PublicKeyInfo	PublicKeyInfo	`bson:",inline"`
	Meta			KeyPairMeta		`bson:",inline"`
	OwnerUserId     string     		`bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
}

// Standard expected properties: id (did#id), type, controller, publicKeyBase58
type PublicKeyExport struct {	// controller is the blockchain's DID of the entity e.g. "did:v1:uuid:804c6ac3-ce3b-46ce-b134-17175d5bee74"
	PublicKeyInfo	PublicKeyInfo	`bson:",inline"`
	Context      	[]string		`bson:"@context,omitempty" json:"@context,omitempty"`		// "@context": ["https://w3id.org/security/v2"]
	Controller		string			`bson:"controller,omitempty" json:"controller,omitempty"`	// already included in the public 'id' by IdWithDid
	PublicKeyBase58 string     		`bson:"publicKeyBase58,omitempty" json:"publicKeyBase58,omitempty"`	// standard
}

type KeyRetrievalRequest struct {
	AccessPassword  string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	EncryptionKeyID string `bson:"encryptionKeyId,omitempty" json:"encryptionKeyId,omitempty"`
}

type KeyCreationRequest struct {
	AccessPassword string `bson:"accessPassword,omitempty" json:"accessPassword,omitempty"`
	Tag            string `bson:"tag,omitempty" json:"tag,omitempty"`
}

type KeyPairStorageResponse struct {
	Code    int    				`bson:"code,omitempty" json:"code,omitempty"`
	Count   int64  				`bson:"count,omitempty" json:"count,omitempty"`
	Message string 				`bson:"message,omitempty" json:"message,omitempty"`
	Data    []KeyPairStorage	`bson:"data,omitempty" json:"data,omitempty"`
}

type PublicInfoByActiveKeyResponse struct {
	Code    int                   	`bson:"code,omitempty" json:"code,omitempty"`
	Count   int64                  	`bson:"count,omitempty" json:"count,omitempty"`
	Message string                 	`bson:"message,omitempty" json:"message,omitempty"`
	Data    []PublicInfoByActiveKey `bson:"data,omitempty" json:"data,omitempty"`
}

// ----------------------- OLD  ----------------------------

// TODO: should be used 'KeyPairStorage' instead of 'Key'
type Key struct {				// public and private key pair, not a single public key
	ID               string     `bson:"id,omitempty" json:"id,omitempty"`	// Identifier of this public key in the Blockchain's DID Document
	WalletKeyId      string     `bson:"walletKeyId,omitempty" json:"walletKeyId,omitempty"`	// Wallet's identifier of this public key
	Tag              string     `bson:"tag,omitempty" json:"tag,omitempty"`
	Capability       string     `bson:"capability,omitempty" json:"capability,omitempty"`
	Type             string     `bson:"type,omitempty" json:"type,omitempty"`
	CreatedAt        *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt        *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	PublicKeyBase64  string     `bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	PrivateKeyBase64 string     `bson:"privateKeyBase64,omitempty" json:"privateKeyBase64,omitempty"`
}

// TODO: should be used 'PublicInfoByActiveKey' instead of 'PublicInfoFromActiveKey'
type PublicInfoFromActiveKey struct {
	ID              string     `bson:"id,omitempty" json:"id,omitempty"`
	Tag             string     `bson:"tag,omitempty" json:"tag,omitempty"`
	OwnerUserId     string     `bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
	PublicKeyBase64 string     `bson:"publicKeyBase64,omitempty" json:"publicKeyBase64,omitempty"`
	CreatedAt       *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt       *time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}

// TODO: should be used 'KeyPairStorageResponse' instead of 'KeyResponse'
type KeyResponse struct {
	Code    int    	`bson:"code,omitempty" json:"code,omitempty"`
	Count   int64  	`bson:"count,omitempty" json:"count,omitempty"`
	Message string 	`bson:"message,omitempty" json:"message,omitempty"`
	Data    []Key  	`bson:"data,omitempty" json:"data,omitempty"`
}

// TODO: should be used 'PublicInfoByActiveKeyResponse' instead of 'PublicInfoFromKeyResponse'
type PublicInfoFromKeyResponse struct {
	Code    int                       `bson:"code,omitempty" json:"code,omitempty"`
	Count   int64                     `bson:"count,omitempty" json:"count,omitempty"`
	Message string                    `bson:"message,omitempty" json:"message,omitempty"`
	Data    []PublicInfoFromActiveKey `bson:"data,omitempty" json:"data,omitempty"`
}


