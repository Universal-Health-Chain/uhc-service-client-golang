package commonManagers

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/stretchr/testify/require"
	"testing"
)

var keyPairManager = KeyPairManager{}

func Test_CreateEd25519SignKeyPair(t *testing.T) {
	signKeyPair,err := keyPairManager.CreateEd25519SignKeyPair(walletIdForTesting, "", nil, "")
	require.NoError(t, err)
	require.NotEmpty(t, signKeyPair.ID)
	require.NotEmpty(t, signKeyPair.Meta.Created)
	require.NotEmpty(t, signKeyPair.PublicKeyInfo.PublicKeyBase64)
	require.NotEmpty(t, signKeyPair.PrivateKeyInfo.WalletId)
	require.NotEmpty(t, signKeyPair.PrivateKeyInfo.PrivateKeyBase64)
	require.Equal(t, signKeyPair.PublicKeyInfo.Type, Ed25519KeyType)	// "Ed25519VerificationKey2018"
	require.Empty(t, signKeyPair.Meta.Tag)
	require.Empty(t, signKeyPair.PublicKeyInfo.IdWithDid)
	require.Empty(t, signKeyPair.PublicKeyInfo.Expires)
	require.Empty(t, signKeyPair.PublicKeyInfo.Revoked)
	require.Empty(t, signKeyPair.PrivateKeyInfo.Purposes)

	println("signKeyPair.PublicKeyInfo.PublicKeyBase64 = ", signKeyPair.PublicKeyInfo.PublicKeyBase64)	// hexadecimal
	publicSignKeyBytes, err := Base64StringToBytes(signKeyPair.PublicKeyInfo.PublicKeyBase64)
	privateSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyInfo.PrivateKeyBase64)

	// It creates the signer entity with the generated keys
	signerEntity := signature.GetEd25519Signer(privateSignKeyBytes, publicSignKeyBytes)
	require.NotEmpty(t, signerEntity.PublicKeyBytes)
	require.Equal(t, signerEntity.PublicKeyBytes(), publicSignKeyBytes)

	// PublicKey returns a public key object (e.g. ed25519.PublicKey)
	println("signerEntity.PublicKey = ", signerEntity.PublicKey)	// hexadecimal
}

func Test_CreateX25519EncryptKeyPair(t *testing.T) {
	encryptKeyPair,err := keyPairManager.CreateX25519EncryptKeyPair(walletIdForTesting, "", nil, "")
	require.NoError(t, err)
	require.NotEmpty(t, encryptKeyPair.ID)
	require.NotEmpty(t, encryptKeyPair.Meta.Created)
	require.NotEmpty(t, encryptKeyPair.PublicKeyInfo.PublicKeyBase64)
	require.NotEmpty(t, encryptKeyPair.PrivateKeyInfo.WalletId)
	require.NotEmpty(t, encryptKeyPair.PrivateKeyInfo.PrivateKeyBase64)
	require.Equal(t, encryptKeyPair.PublicKeyInfo.Type, X25519KeyType) // "X25519KeyAgreementKey2019"
	require.Empty(t, encryptKeyPair.Meta.Tag)
	require.Empty(t, encryptKeyPair.PublicKeyInfo.IdWithDid)
	require.Empty(t, encryptKeyPair.PublicKeyInfo.Expires)
	require.Empty(t, encryptKeyPair.PublicKeyInfo.Revoked)
	require.Empty(t, encryptKeyPair.PrivateKeyInfo.Purposes)

	println("encryptKeyPair.PublicKeyInfo.PublicKeyBase64 = ", encryptKeyPair.PublicKeyInfo.PublicKeyBase64) // hexadecimal
	// publicEncryptKeyBytes, err := Base64StringToBytes(encryptKeyPair.PublicKeyInfo.PublicKeyBase64)
	// privateEncryptKeyBytes, err := Base64StringToBytes(encryptKeyPair.PrivateKeyInfo.PrivateKeyBase64)

}
