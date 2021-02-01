package commonManagers

import (
	"cloud.google.com/go/pubsub"
	"context"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"

	// "github.com/google/tink/go/aead"
	// "github.com/google/tink/go/core/registry"
	// "github.com/google/tink/go/keyset"
	// "github.com/google/tink/go/integration/gcpkms"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// serviceAccount shows how to use a service account to authenticate.
func Test_GoogleServiceAccountCredential(t *testing.T)  {
	// Download service account key per https://cloud.google.com/docs/authentication/production.
	// Set environment variable GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
	// This environment variable will be automatically picked up by the client.
	client, err := pubsub.NewClient(context.Background(), "your-project-id")
	if err != nil { fmt.Printf("pubsub.NewClient: %v", err)}
	require.NoError(t, err)

	// Use the authenticated client.
	_ = client
}

func Test_GClientIntegrationTink(t *testing.T){
	_ = godotenv.Load("../.env")
	environment := os.Getenv("ENVIRONMENT")
	keyURI := os.Getenv("KEYURI" + "_" + environment)

	gcpClient, err := gcpkms.NewClientWithCredentials(keyURI, "/users/fernando/Documents/uhc-healthcare-project-owner.json")
	// gcpClient, err := gcpkms.NewClient(keyURI)
	require.NoError(t, err)

	registry.RegisterKMSClient(gcpClient)

	dek := aead.AES256GCMKeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	require.NoError(t, err)

	a, err := aead.New(kh)
	require.NoError(t, err)

	ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("this data needs to be authenticated, but not encrypted"))
	require.NoError(t, err)

	_, err = a.Decrypt(ct, []byte("this data needs to be authenticated, but not encrypted"))
	require.NoError(t, err)
}

func Test_TinkKeySetHandle(t *testing.T) {
	_ = godotenv.Load("../.env")
	environment := os.Getenv("ENVIRONMENT")
	keyURI := os.Getenv("KEYURI" + "_" + environment)

	// It creates the required manager
	var keyManager KeyPairManager

	// Generate a new key: It creates a new sender
	keysetHandle1, err := keyManager.CreateAuthcryptKeysetHandle()
	require.NoError(t, err)

	// Fetch the master key from a KMS.
	// gcpClient, err := gcpkms.NewClient(keyURI)
	gcpClient, err := gcpkms.NewClientWithCredentials(keyURI, "/users/fernando/Documents/uhc-healthcare-project-owner.json")
	require.NoError(t, err)
	registry.RegisterKMSClient(gcpClient)

	backend, err := gcpClient.GetAEAD(keyURI)
	require.NoError(t, err)
	masterKey := aead.NewKMSEnvelopeAEAD(*aead.AES256GCMKeyTemplate(), backend)

	// An io.Reader and io.Writer implementation which simply writes to memory (no backend store)
	memKeyset := &keyset.MemReaderWriter{}

	// Write encrypts the keyset handle with the master key and writes to the io.Writer implementation (memKeyset).
	// CAUTION: The keyset handle always must be encrypted before persisting it.
	err = keysetHandle1.Write(memKeyset, masterKey)
	require.NoError(t, err)

	publicKeyKH1,err := keyPairManager.GetPublicCompositeKeyByKeyset(keysetHandle1)
	require.NotEmpty(t, publicKeyKH1)

	// Read reads the encrypted keyset handle back from the io.Reader implementation
	// and decrypts it using the master key.
	kh2, err := keyset.Read(memKeyset, masterKey)
	require.NoError(t, err)

	publicKeyKH2,err := keyPairManager.GetPublicCompositeKeyByKeyset(kh2)
	require.NotEmpty(t, publicKeyKH2)
	require.Equal(t, publicKeyKH1, publicKeyKH2) // "key handlers are equal

	// Test GetPublicKeyBytesByKeyset
	publicKeyBytes,err := keyPairManager.GetPublicKeyBytesByKeyset(keysetHandle1)
	require.NoError(t, err)
	require.NotNil(t, publicKeyBytes)
}