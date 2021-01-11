/* Copyright 2021 Fundación UNID */
package models

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hash"
	"strings"
)

func GetHashLegacySHA1AsHexString(bytes []byte) string {
	digestValue, _ := GetDigestValue("SHA1", bytes)
	return digestValue
}

// The Keccak team recommends SHAKE256 for most applications upgrading from SHA2-512 (at least 64 bytes, variable length)
// instead of using SHA3-256 ("drop-in" replacement for SHA2-256 but with 32 bytes, fixed length)
// but currently only fixed-length SHA-3 algorithms (not SHAKE) are approved by NIST as alternative to the SHA-2 hash functions
// and NIST chose the stronger, but much slower, sponge instance for SHA3-512 (64 bytes fixed length).

func GetHashKeccakShake256AsHexString(bytes []byte) string {
	shake256Hash := GetHashKeccakShake256Bytes(bytes) // SHAKE256 has an arbitrary output length of at least 64 bytes
	shake256ResultHexString := hex.EncodeToString(shake256Hash)
	fmt.Printf("SHAKE256 bytes encoded to string in hex format= %s \n", shake256ResultHexString)
	return shake256ResultHexString
}

func GetHashKeccakShake256Bytes(bytes []byte) []byte {
	shake256Hash := make([]byte, 64)		// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	sha3.ShakeSum256(shake256Hash, bytes)	// Compute a 64-byte hash of buf and put it in shake256Hash.
	return shake256Hash
}

func GetHashSHA3256AsHexString(bytes []byte) string {
	digestValue, _ := GetDigestValue("SHA3256", bytes)
	return digestValue
}

// GetDigestValue returns the digest of some data, using a specified algorithm.
// It only returns an error when an invalid algorithm is used.
// The valid ones are: SHA1, SHA256, SHA512, SHA3256, and SHA3512.
func GetDigestValue(algorithm string, data []byte) (digestValue string, err error) {
	var hasher hash.Hash
	switch strings.ToUpper(algorithm) {
	// case "MD5": hasher = md5.New()
	case "SHA1": hasher = sha1.New()
	case "SHA256": hasher = sha256.New()
	case "SHA512": hasher = sha512.New()
	case "SHA3256": hasher = sha3.New256()
	case "SHA3512": hasher = sha3.New512()
	default:
		msg := "Invalid algorithm parameter passed go Checksum: %s"
		return digestValue, fmt.Errorf(msg, algorithm)
	}
	hasher.Write(data)
	digestBytes := hasher.Sum(nil)
	digestValue = hex.EncodeToString(digestBytes)
	return digestValue, nil
}

/*
type ChallengeToSign struct {  // see https://w3c-ccg.github.io/security-vocab/
	Type            string     `bson:"type,omitempty" json:"@type,omitempty"`						// type of signature to be used, "Ed25519Signature2018" is the default
	Challenge       string     `bson:"challenge,omitempty" json:"challenge,omitempty"`				// hexadecimal SHA3-256 digest value (base-16 format) or UUID random v4 strings
	Purposes      string     `bson:"capability,omitempty" json:"capability,omitempty"`			// to use the cryptographic keys associated with the required capability
	ProofPurpose    string     `bson:"proofPurpose,omitempty" json:"proofPurpose,omitempty"`		// the purpose of the signature: "digest", "authentication", "assertionMethod" ...
}
*/

type DigestToSign struct {  // see https://w3c-ccg.github.io/security-vocab/
	Type            string     `bson:"type,omitempty" json:"type,omitempty"`						// "@type": "Digest"
	Context      	[]string	`bson:"context,omitempty" json:"@context,omitempty"`      			// "@context": ["https://w3id.org/security/v1"]
	DigestValue     string     `bson:"digestValue,omitempty" json:"digestValue,omitempty"`				// hexadecimal SHA3-256 digest value (base-16 format) or UUID random v4 strings
	DigestAlgorithm	string     `bson:"digestAlgorithm,omitempty" json:"digestAlgorithm,omitempty"`	// if challenge is a digest: "sha3-256"
	Capability      string     `bson:"capability,omitempty" json:"capability,omitempty"`			// to use the cryptographic keys associated with the required capability
	ProofPurpose    string     `bson:"proofPurpose,omitempty" json:"proofPurpose,omitempty"`		// the purpose of the signature: "digest", "authentication", "assertionMethod" ...
}

type DigestSigned struct {     // see https://w3c-ccg.github.io/security-vocab/#Digest
	DigestToSign	DigestToSign	`bson:",inline"`
	Proof           []proof.Proof	`bson:"proof,omitempty" json:"proof,omitempty"`   					// the signature proof
}

type HashDltOutput struct {
	Id             	string	`bson:"id,omitempty" json:id",omitempty"`							// UUID random v4 identifying document's digest value
	DigestValue     string	`bson:"digestValue,omitempty" json:digestValue",omitempty"`			// hexadecimal digest value in base-16 format
	DigestAlgorithm	string	`bson:"digestAlgorithm,omitempty" json:digestAlgorithm",omitempty"`	// "sha3-256" or other hash function used when generating document's digest value
	TxTimestampISO	string	`bson:"txTimestamp,omitempty" json:txTimestamp",omitempty"`			// the timestamp of the blockchain transaction
	TxId            string	`bson:"txId,omitempty" json:txId",omitempty"`						// the identifier of the blockchain transaction
}

