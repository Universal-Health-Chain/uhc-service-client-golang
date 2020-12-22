package models

import "github.com/hyperledger/aries-framework-go/pkg/doc/signature/proof"

package models

type ChallengeToSign struct {  // see https://w3c-ccg.github.io/security-vocab/
	Challenge       string     `bson:"challenge,omitempty" json:challenge",omitempty"`				// hexadecimal SHA3-256 digest value (base-16 format) or UUID random v4 strings
	DigestAlgorithm	string     `bson:"digestAlgorithm,omitempty" json:digestAlgorithm",omitempty"`	// if challenge is a digest: "sha3-256"
	Type            string     `bson:"type,omitempty" json:type",omitempty"`						// type of signature to be used, "Ed25519Signature2018" is the default
	Capability      string     `bson:"capability,omitempty" json:capability",omitempty"`			// to use the cryptographic keys associated with the required capability
	ProofPurpose    string     `bson:"proofPurpose,omitempty" json:proofPurpose",omitempty"`		// the purpose of the signature: "digest", "authentication", "assertionMethod" ...
}

type DigestSigned struct {     // see https://w3c-ccg.github.io/security-vocab/#Digest
	Context      	[]string	`bson:"context,omitempty" json:@context",omitempty"`      			// "@context": ["https://w3id.org/security/v1"]
	Type         	string      `bson:"type,omitempty" json:@type",omitempty"`  					// "@type": "Digest"
	DigestValue     string      `bson:"digestValue,omitempty" json:digestValue",omitempty"` 		// hexadecimal SHA3-256 digest value (base-16 format) or UUID random v4 strings
	DigestAlgorithm	string      `bson:"digestAlgorithm,omitempty" json:digestAlgorithm",omitempty"` // the cryptographic function used when generating the data digitally signed
	Proof           proof.Proof	`bson:"proof,omitempty" json:proof",omitempty"`   					// the signature proof
}
/* Using the imported proof.Proof
type DigestProof struct {		// see https://w3c-ccg.github.io/security-vocab/#Ed25519Signature2018
	Type               	string  `bson:"context,omitempty" json:@context",omitempty"`						// default "Ed25519Signature2018"
	VerificationMethod	string  `bson:"verificationMethod,omitempty" json:verificationMethod",omitempty"`   // did#signPublicKey to get the publicKey for verifying the JWS payload's signature
	JWS                	string  `bson:"jws,omitempty" json:jws",omitempty"`   								// the signature of the digestValue by using Ed25519Signature2018
	Created          	string  `bson:"created,omitempty" json:created",omitempty"`   						// Date.toISOstring()
	ProofPurpose     	string	`bson:"proofPurpose,omitempty" json:proofPurpose",omitempty"`				// the purpose of the signature: "digest", "authentication", "assertionMethod" ...
}
*/
type HashDltOutput struct {
	Id             	string	`bson:"id,omitempty" json:id",omitempty"`							// UUID random v4 identifying document's digest value
	DigestValue     string	`bson:"digestValue,omitempty" json:digestValue",omitempty"`			// hexadecimal digest value in base-16 format
	DigestAlgorithm	string	`bson:"digestAlgorithm,omitempty" json:digestAlgorithm",omitempty"`	// "sha3-256" or other hash function used when generating document's digest value
	TxTimestampISO	string	`bson:"txTimestamp,omitempty" json:txTimestamp",omitempty"`			// the timestamp of the blockchain transaction
	TxId            string	`bson:"txId,omitempty" json:txId",omitempty"`						// the identifier of the blockchain transaction
}

