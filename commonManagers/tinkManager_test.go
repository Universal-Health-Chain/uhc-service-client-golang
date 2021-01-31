
package commonManagers

// For creating keys: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
// KEK (Key Encription Key) is in remote KMS. DEK (Database-Encryption Key) is encripted with KEK in the local database.
// There are two keys between the user and the data: the database-encryption key (DEK) or column-encryption key (CEK)
// Some concepts: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets

/* https://github.com/google/tink/blob/master/docs/KEY-MANAGEMENT.md
Tink provides support for key management features like key versioning, key rotation, and storing keysets
	or encrypting with master keys in remote key management systems (KMS).

The process of encrypting data is to generate a DEK locally, encrypt data with the DEK, use a KEK to wrap the DEK,
and then store the encrypted data and the wrapped DEK. The KEK never leaves Cloud KMS.

Envelope encryption: Via the AEAD interface, Tink supports envelope encryption in tandem with GCP and AWS KMS.
You first create a key encryption key (KEK) in a Key Management System (KMS) such as AWS KMS or Google Cloud KMS.
To encrypt some data, you then locally generate a data encryption key (DEK), encrypt data (e.g. private keys) with the DEK,
	ask the KMS to encrypt the DEK with the KEK, and store the encrypted DEK with the encrypted data in a secure way.
At a later point, you can retrieve the encrypted data and the encrypted DEK, ask the KMS to decrypt the DEK, and use the decrypted DEK to decrypt the data.

Tink performs cryptographic tasks via so-called primitives,
	each of which is defined via a corresponding interface that specifies the functionality of the primitive.

Tink/Tinkey can encrypt or decrypt keysets with master keys residing in remote KMSes. Currently, the following KMSes are supported:
	- Google Cloud KMS
	- AWS KMS
	- Android Keystore
	- On iOS, Tink can also directly load or store keysets in iOS KeyChain.
*/

// For creating keys: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
// KEK (Key Encription Key) is in remote KMS. DEK (Database-Encryption Key) is encripted with KEK in the local database.
// There are two keys between the user and the data: the database-encryption key (DEK) or column-encryption key (CEK)
// Some concepts: https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#keysets

/* https://cloud.google.com/kms/docs/resource-hierarchy?_ga=2.216942547.-458293874.1603516054#key
The purpose of a symmetric key is always Symmetric encrypt/decrypt.
The purpose of an asymmetric key is either Asymmetric encrypt/decrypt or Asymmetric signing.
A key's purpose can't be changed after the key is created.

Primary version: A key has multiple versions, but a symmetric key can have at most one primary key version. The primary key version is used to encrypt data if you do not specify a key version.
Asymmetric keys do not have primary versions; you must specify the version when using the key.
For both symmetric and asymmetric keys, you can use any enabled key version to encrypt or decrypt data, whether it is the primary version or not.

Key ring: 		projects/project-id/locations/location/keyRings/keyring
Key:			projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key
Key version:	projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key/cryptoKeyVersions/version

The process of encrypting data is to generate a DEK locally, encrypt data with the DEK, use a KEK to wrap the DEK,
	and then store the encrypted data and the wrapped DEK. The KEK never leaves Cloud KMS.

Here are best practices for managing DEKs:
- Generate DEKs locally.
- When stored, always ensure DEKs are encrypted at rest.
- For easy access, store the DEK near the data that it encrypts.
- Generate a new DEK every time you write the data. This means you don't need to rotate the DEKs.
- Do not use the same DEK to encrypt data from two different users.
- Use a strong algorithm such as 256-bit Advanced Encryption Standard (AES) in Galois Counter Mode (GCM).

*/

import (
	"fmt"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/joho/godotenv"
	"log"
	"os"
	"testing"

	"encoding/base64"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	// "github.com/google/tink/go/core/registry"
	// "github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/tink/go/insecurecleartextkeyset"
)

func Test_CreateLibsodiumKeyBySeed(t *testing.T) {
	/*  pkg-config --cflags  -- libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium libsodium
	pkg-config: exec: "pkg-config": executable file not found in $PATH
	seed := sodium.BoxSeed{}
	sodium.Randomize(&seed)
	kp1 := sodium.SeedBoxKP(seed)
	kp2 := sodium.SeedBoxKP(seed)
	s1 := kp1.SecretKey
	s2 := kp2.SecretKey

	fmt.Println(sodium.MemCmp(s1.Bytes, s2.Bytes, s1.Length()) == 0)
	require.Equal(t, s1.Bytes, s2.Bytes)

	 */
}

// Example based on https://gist.github.com/salrashid123/2e5f6e7cc8e479fad0909412a86892eb
// and https://medium.com/google-cloud/google-cloud-kms-tink-1e106156bb4e
func Test_TinkGoogleKMS(t *testing.T) {
	// keyURI := fmt.Sprintf("gcp-kms://projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", *project, *location, *keyring, *key)
	godotenv.Load("../.env")
	environment := os.Getenv("ENVIRONMENT")
	keyURI := os.Getenv("KEYURI" + "_" + environment)
	fmt.Println("KeyURI = ", keyURI)

	// Fetch the master KEK (Key Encryption Key) from the KMS
	kmsClient, err := gcpkms.NewClient(keyURI)
	if err != nil { log.Print(err) }
	registry.RegisterKMSClient(kmsClient)

	// Gets an AEAD backend by keyURI instead of creating a new DEK template
	masterKeyAEAD, err := kmsClient.GetAEAD(keyURI)

	// Creates a new type of database-encryption key (DEK) for the backend by using a template
	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()

	// creates a keyset handle that contains a new DEK key generated with both the given KeyTemplate and KEK's URI
	dekKeysetHandle, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dekTemplate))
	// dekKeysetHandle, err = keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil { log.Print(err) }

	// An io.Reader and io.Writer implementation which simply writes to memory.
	memKeysetWriter := &keyset.MemReaderWriter{}

	// insecurecleartextkeyset provides dangerous functions to read or write cleartext keyset material
	// and is separate from the rest of Tink so that its usage can be restricted and audited.
	if err := insecurecleartextkeyset.Write(dekKeysetHandle, memKeysetWriter); err != nil {
		log.Print(err)
	}
	keysetInsecure, err := proto.Marshal(memKeysetWriter.Keyset)
	if err != nil { log.Print(err) }
	log.Printf("%s", base64.RawStdEncoding.EncodeToString(keysetInsecure))

	// Marshaler is newAEAD configurable object for converting between protocol buffer objects and newAEAD JSON representation for them.
	protoBufferMarshaler := jsonpb.Marshaler{}
	keysetInsecureString, err := protoBufferMarshaler.MarshalToString(memKeysetWriter.Keyset)
	if err != nil { log.Print(err) }
	log.Printf("Insecure Keyset data = %s\n", keysetInsecureString)

	// Creates a new keyset handle that contains a single fresh new key,
	// according to the given KeyTemplate for the DEK (Database Encryption Key)
	newKeysetHandle, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dekTemplate))
	if err != nil { log.Print(err) }

	// New AEAD primitive from the given keyset handle (created with the DEK template and the KEK's keyURI in the KMS)
	newAEAD, err := aead.New(newKeysetHandle)
	if err != nil { log.Print(err) }

	// Encrypt encrypts plaintext with additionalData as additional authenticated data
	ciphertext, err := newAEAD.Encrypt([]byte("this data needs to be encrypted"), []byte("associated data"))
	if err != nil { log.Print(err) }

	// Decrypt decrypts ciphertext with {@code additionalData} as additional authenticated data.
	plaintext, err := newAEAD.Decrypt(ciphertext, []byte("associated data"))
	if err != nil { log.Print(err) }

	fmt.Printf("Cipher text: \n%s\n\n", base64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("Plain text: %s\n", plaintext)

	// Write encrypts the keyset handle with the master key and writes to the io.Writer implementation (memKeyset).
	// We recommend you encrypt the keyset handle before persisting it.
	kh1, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())	// Generate a new key.
	if err != nil { log.Print(err) }
	if err := newKeysetHandle.Write(memKeysetWriter, masterKeyAEAD); err != nil {
		log.Print(err)
	}

	// Read reads the encrypted keyset handle back from the io.Reader implementation
	// and decrypts it using the master key.
	kh2, err := keyset.Read(memKeysetWriter, masterKeyAEAD)
	if err != nil { log.Print(err) }

	if kh1 != kh2 {
		log.Print("key handlers are not equal")
	} else {
		fmt.Println("Key handlers are equal.")
	}

}


