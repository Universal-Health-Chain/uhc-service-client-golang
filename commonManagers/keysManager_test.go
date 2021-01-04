package commonManagers

import (
	"crypto/ed25519"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// from Aries verifiable_test - Sign key generated by ed25519.GenerateKey(rand.Reader).
//nolint:gochecknoglobals

var (
	Ed25519PrivateKeyBytesForTesting = ed25519.PrivateKey{72, 67, 163, 188, 235, 199, 239, 146, 129, 52, 228, 34, 44, 106, 23, 144, 189, 57, 115, 171, 4, 217, 54, 121, 41, 155, 251, 83, 1, 240, 238, 65, 234, 100, 192, 93, 251, 181, 198, 73, 122, 220, 27, 48, 93, 73, 166, 33, 152, 140, 168, 36, 9, 205, 59, 161, 137, 7, 164, 9, 176, 252, 1, 171} //nolint:lll
	Ed25519PublicKeyBytesForTesting  = ed25519.PublicKey{234, 100, 192, 93, 251, 181, 198, 73, 122, 220, 27, 48, 93, 73, 166, 33, 152, 140, 168, 36, 9, 205, 59, 161, 137, 7, 164, 9, 176, 252, 1, 171} //nolint:lll
	Ed25519PrivateKeyB64ForTesting   = "SEOjvOvH75KBNOQiLGoXkL05c6sE2TZ5KZv7UwHw7kHqZMBd+7XGSXrcGzBdSaYhmIyoJAnNO6GJB6QJsPwBqw==" //nolint:lll
	Ed25519PublicKeyB64ForTesting    = "6mTAXfu1xkl63BswXUmmIZiMqCQJzTuhiQekCbD8Aas="

	CreatedTImeForTesting            = time.Date(2020, time.January, 1, 20, 21, 22, 0, time.UTC)
	ExpiresTimeForTesting            = time.Date(2030, time.January, 1, 20, 21, 22, 0, time.UTC)

	X25519PrivateKeyB64ForTesting	= "4mpJAw2mbtkLZQxUb2YSxwOnMRzRnzrsTBG+cZTvn+0="
	X25519PublicKeyB64ForTesting	= "bGAczi4Kw77rEYdnIEAyLpToQgSxP7XgEuXUzuFv9xk="

	bbsPrivKeyB64               	= "PcVroyzTlmnYIIq8In8QOZhpK72AdTjj3EitB9tSNrg"
	bbsPubKeyB64                	= "l0Wtf3gy5f140G5vCoCJw2420hwk6Xw65/DX3ycv1W7/eMky8DyExw+o1s2bmq3sEIJatkiN8f5D4k0766x0UvfbupFX+vVkeqnlOvT6o2cag2osQdMFbBQqAybOM4Gm" //nolint:lll
)

const UhcUserIdForTesting		= "5d96ea7b-ed86-4f73-b181-c32c0bd9a17e"
const UhcDeviceIdForTesting 	= "9923f4aa-baa5-4851-97ca-329d8c9551c6"
const WalletIdForTesting 		= "f090bc28-0d84-45be-817e-87a002455212"

const UserDIDForTesting 		= DIDMethod + UhcUserIdForTesting
const DeviceDIDForTesting 		= DIDMethod + UhcDeviceIdForTesting

const UserSignPublicKeyID 		= "aaab749d-ccfc-44a7-9bbc-b7d22999ff5f"
const UserVerifyPublicKeyDID 	= UserDIDForTesting + "#" + UserSignPublicKeyID

const UserEncryptPublicKeyID 	= "2412b88c-6a70-494f-8cd1-f43acc4b852c"
const UserEncryptPublicKeyDID 	= UserDIDForTesting + "#" + UserEncryptPublicKeyID

var UserForTesting = &models.User{
	ID:            UhcUserIdForTesting,
	DidController: UserDIDForTesting,
}

var Ed25519SignKeyPairForTesting = models.Key{
	ID:				UserSignPublicKeyID,
	ControllerDID:	UserDIDForTesting,		// DIDMethod + UhcUserId
	PublicKeyDID:	UserVerifyPublicKeyDID,	// ControllerDID + "#" + signKeyPair.ID
	Type:           Ed25519KeyType,
	Usage:          models.KeyUsageSigning,
	Tag:            "tag",
	CreatedAt:      &CreatedTImeForTesting,
	Capability:     DefaultProofPurpose,
	WalletKeyId:    WalletIdForTesting,
	PublicKeyBase64: BytesToBase64String(Ed25519PublicKeyBytesForTesting),
	PrivateKeyBase64:BytesToBase64String(Ed25519PrivateKeyBytesForTesting),
	// UpdatedAt:        &time.Time{},
	// Expires:          &time.Time{},
	// Revoked:          &time.Time{},
	// Purposes: []"purposes",
}

var X25519EncryptKeyPairForTesting = models.Key{
	ID:				UserEncryptPublicKeyID,
	ControllerDID:	UserDIDForTesting,		// DIDMethod + UhcUserId
	PublicKeyDID:   UserEncryptPublicKeyDID,// ControllerDID + "#" + signKeyPair.ID
	Type:           X25519KeyType,
	Usage:          models.KeyUsageEncryption,
	Tag:            "tag",
	CreatedAt:      &CreatedTImeForTesting,
	// Capability:  "",
	WalletKeyId:    WalletIdForTesting,
	PublicKeyBase64: X25519PublicKeyB64ForTesting,
	PrivateKeyBase64:X25519PrivateKeyB64ForTesting,
	// UpdatedAt:        &time.Time{},
	// Expires:          &time.Time{},
	// Revoked:          &time.Time{},
	// Purposes: []"purposes",
}

var keyPairManager = KeyPairManager{}

func Test_CreateEd25519SignKeyPair(t *testing.T) {
	// Only for testing
	// println("Ed25519PrivateKeyBytesForTesting = ", base64.StdEncoding.EncodeToString(Ed25519PrivateKeyBytesForTesting))
	// println("Ed25519PublicKeyBytesForTesting = ", base64.StdEncoding.EncodeToString(Ed25519PublicKeyBytesForTesting))

	signKeyPair,err := keyPairManager.CreateEd25519SignKeyPair(WalletIdForTesting, UhcUserIdForTesting, []string{"test"}, "")
	require.NoError(t, err)
	require.NotEmpty(t, signKeyPair.ID)
	require.NotEmpty(t, signKeyPair.CreatedAt)
	require.NotEmpty(t, signKeyPair.PublicKeyBase64)
	require.NotEmpty(t, signKeyPair.WalletKeyId)
	require.NotEmpty(t, signKeyPair.PrivateKeyBase64)
	require.Equal(t, signKeyPair.Type, Ed25519KeyType)		// "Ed25519VerificationKey2018"
	require.Equal(t, signKeyPair.Capability, "test")	// TODO: change to Purposes
	require.Equal(t, signKeyPair.PublicKeyDID, DIDMethod + UhcUserIdForTesting + "#" + signKeyPair.ID)
	require.Empty(t, signKeyPair.Tag)
	require.Empty(t, signKeyPair.Expires)
	require.Empty(t, signKeyPair.Revoked)

	// Only for testing
	println("signKeyPair.PublicKeyBase64 = ", signKeyPair.PublicKeyBase64)
	println("signKeyPair.PrivateKeyBase64 = ", signKeyPair.PrivateKeyBase64)

	publicSignKeyBytes, err := Base64StringToBytes(signKeyPair.PublicKeyBase64)
	privateSignKeyBytes, err := Base64StringToBytes(signKeyPair.PrivateKeyBase64)

	// It creates the signer entity with the generated keys
	signerEntity := signature.GetEd25519Signer(privateSignKeyBytes, publicSignKeyBytes)
	require.NotEmpty(t, signerEntity.PublicKeyBytes)
	require.Equal(t, signerEntity.PublicKeyBytes(), publicSignKeyBytes)

	// PublicKey returns a public key object (e.g. ed25519.PublicKey)
	println("signerEntity.PublicKey = ", signerEntity.PublicKey)	// hexadecimal?
}

func Test_CreateX25519EncryptKeyPair(t *testing.T) {
	encryptKeyPair,err := keyPairManager.CreateX25519EncryptKeyPair(WalletIdForTesting, UhcUserIdForTesting, []string{"test"}, "")
	require.NoError(t, err)
	fmt.Printf("encryptKeyPair = %v \n", encryptKeyPair)

	require.NotEmpty(t, encryptKeyPair.ID)
	require.NotEmpty(t, encryptKeyPair.CreatedAt)
	require.NotEmpty(t, encryptKeyPair.PublicKeyBase64)
	require.NotEmpty(t, encryptKeyPair.WalletKeyId)
	require.NotEmpty(t, encryptKeyPair.PrivateKeyBase64)
	require.Equal(t, encryptKeyPair.Type, X25519KeyType) // "X25519KeyAgreementKey2019"
	require.Equal(t, encryptKeyPair.Capability, "test")	// TODO: change to Purposes
	require.Equal(t, encryptKeyPair.PublicKeyDID, DIDMethod + UhcUserIdForTesting + "#" + encryptKeyPair.ID)
	require.Empty(t, encryptKeyPair.Tag)
	require.Empty(t, encryptKeyPair.Expires)
	require.Empty(t, encryptKeyPair.Revoked)

	// Only for testing
	println("encryptKeyPair.PublicKeyBase64 = ", encryptKeyPair.PublicKeyBase64)
	println("encryptKeyPair.PrivateKeyBase64 = ", encryptKeyPair.PrivateKeyBase64)
}
