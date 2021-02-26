package commonManagers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/tink/go/subtle/random"
	"math/big"
	"testing"

	// "github.com/google/tink/go/subtle"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto"

	gojose3 "github.com/square/go-jose/v3"

	"github.com/google/tink/go/aead"
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	// "github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	// "github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	gojose "github.com/square/go-jose/v3"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/jose"
	sigverifier "github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/verifier"
	signutil "github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/util/signature"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"

	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"

	cryptoapi "github.com/Universal-Health-Chain/aries-framework-go/pkg/crypto"
	kmsapi "github.com/Universal-Health-Chain/aries-framework-go/pkg/kms"
)


// Key management algorithms
const (
	ED25519            = gojose3.KeyAlgorithm("ED25519")
	RSA1_5             = gojose3.KeyAlgorithm("RSA1_5")             // RSA-PKCS1v1.5
	RSA_OAEP           = gojose3.KeyAlgorithm("RSA-OAEP")           // RSA-OAEP-SHA1
	RSA_OAEP_256       = gojose3.KeyAlgorithm("RSA-OAEP-256")       // RSA-OAEP-SHA256
	A128KW             = gojose3.KeyAlgorithm("A128KW")             // AES key wrap (128)
	A192KW             = gojose3.KeyAlgorithm("A192KW")             // AES key wrap (192)
	A256KW             = gojose3.KeyAlgorithm("A256KW")             // AES key wrap (256)
	DIRECT             = gojose3.KeyAlgorithm("dir")                // Direct encryption
	ECDH_ES            = gojose3.KeyAlgorithm("ECDH-ES")            // ECDH-ES
	ECDH_ES_A128KW     = gojose3.KeyAlgorithm("ECDH-ES+A128KW")     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     = gojose3.KeyAlgorithm("ECDH-ES+A192KW")     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     = gojose3.KeyAlgorithm("ECDH-ES+A256KW")     // ECDH-ES + AES key wrap (256)
	A128GCMKW          = gojose3.KeyAlgorithm("A128GCMKW")          // AES-GCM key wrap (128)
	A192GCMKW          = gojose3.KeyAlgorithm("A192GCMKW")          // AES-GCM key wrap (192)
	A256GCMKW          = gojose3.KeyAlgorithm("A256GCMKW")          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW = gojose3.KeyAlgorithm("PBES2-HS256+A128KW") // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW = gojose3.KeyAlgorithm("PBES2-HS384+A192KW") // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW = gojose3.KeyAlgorithm("PBES2-HS512+A256KW") // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

// Signature algorithms
const (
	EdDSA = gojose3.SignatureAlgorithm("EdDSA")
	HS256 = gojose3.SignatureAlgorithm("HS256") // HMAC using SHA-256
	HS384 = gojose3.SignatureAlgorithm("HS384") // HMAC using SHA-384
	HS512 = gojose3.SignatureAlgorithm("HS512") // HMAC using SHA-512
	RS256 = gojose3.SignatureAlgorithm("RS256") // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = gojose3.SignatureAlgorithm("RS384") // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = gojose3.SignatureAlgorithm("RS512") // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = gojose3.SignatureAlgorithm("ES256") // ECDSA using P-256 and SHA-256
	ES384 = gojose3.SignatureAlgorithm("ES384") // ECDSA using P-384 and SHA-384
	ES512 = gojose3.SignatureAlgorithm("ES512") // ECDSA using P-521 and SHA-512
	PS256 = gojose3.SignatureAlgorithm("PS256") // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = gojose3.SignatureAlgorithm("PS384") // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = gojose3.SignatureAlgorithm("PS512") // RSASSA-PSS using SHA512 and MGF1-SHA512
)

// Content encryption algorithms
const (
	A128CBC_HS256 = gojose3.ContentEncryption("A128CBC-HS256") // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384 = gojose3.ContentEncryption("A192CBC-HS384") // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512 = gojose3.ContentEncryption("A256CBC-HS512") // AES-CBC + HMAC-SHA512 (256)
	A128GCM       = gojose3.ContentEncryption("A128GCM")       // AES-GCM (128)
	A192GCM       = gojose3.ContentEncryption("A192GCM")       // AES-GCM (192)
	A256GCM       = gojose3.ContentEncryption("A256GCM")       // AES-GCM (256)
)

// Compression algorithms
const (
	NONE    = gojose3.CompressionAlgorithm("")    // No compression
	DEFLATE = gojose3.CompressionAlgorithm("DEF") // DEFLATE (RFC 1951)
)

// GetEd25519Signer returns Ed25519 Signer with predefined private and public keys.
func GetEd25519Signer(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *Ed25519Signer {
	return &Ed25519Signer{privateKey: privKey, PubKey: pubKey}
}

// CryptoSigner defines signer based on crypto.
type CryptoSigner struct {
	PubKeyBytes []byte
	PubKey      interface{}

	crypto cryptoapi.Crypto
	kh     interface{}
}

// Sign will sign document and return signature.
func (s *CryptoSigner) Sign(msg []byte) ([]byte, error) {
	return s.crypto.Sign(msg, s.kh)
}

// PublicKey returns a public key object (e.g. ed25519.VerificationMethod or *ecdsa.PublicKey).
func (s *CryptoSigner) PublicKey() interface{} {
	return s.PubKey
}

// PublicKeyBytes returns bytes of the public key.
func (s *CryptoSigner) PublicKeyBytes() []byte {
	return s.PubKeyBytes
}

/*
	// if AES then NIST-P256
	encT := aead.AES256GCMKeyTemplate()
	keyURL := nistPECDHKWPublicKeyTypeURL

	if !isAES is XChaCha20Poly1305 and then X25519 (CURVE25519 OKP)
	encT = aead.XChaCha20Poly1305KeyTemplate()
	keyURL = x25519ECDHKWPublicKeyTypeURL
	}
 */

const ephemeralSignPublicKeyBase64 =  "SZ99yFHAe4r7/ttirfBAlzRwjR3mjrRYDaxaPBC9rrs="
const ephemeralSignPrivateKeyBase64 =  "7OqlhX+JykmPp1pVm0h0onKRbgEG5Bmxm6JRy1U9wmNJn33IUcB7ivv+22Kt8ECXNHCNHeaOtFgNrFo8EL2uuw=="
const remoteSignPublicKeyBase64 =  "xjcNXoYkR+zEkKbRvXcflpUUOHsGSS5SwReqb+rskiM="
const remoteSignPrivateKeyBase64 =  "QlsVUpkN+01J+jYGUFcB5qvWd5RZUBaC/PSmzoPjv1vGNw1ehiRH7MSQptG9dx+WlRQ4ewZJLlLBF6pv6uySIw=="
const packedJWE = `{
"ciphertext":"avHk500r0r8xoSCILgNf5eEZyvje73KIJ0DEbqLV-NvUwRGVF6BTa5KcfhfEaa4=",
"iv":"5XDCxPD8xduJmEvfcNTjxF2TRQgqGBYA",
"protected":"eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoiemtmbzNqbTdYd0pCUDlqMi1MSnQ5dGZLekRzQWRBVUZtZ1hzRnc1NUozbURicldoSE4yd1B2LXdDX0FSOE1tdyIsImhlYWRlciI6eyJpdiI6Imx6UkFvX1lHMzRPWjU2eU9nSmRJMGlYTDB4OVZXamJmIiwia2lkIjoiRUxrUXc0Wnp1WktXd2duZUdEM2RBc2FmN3l6bzI4dWdpWlp5WGl0enlLbXQiLCJzZW5kZXIiOiJKbi1LMWFJVTliWER2WDVvS2hORWVHdXd2N1IybHRXWGFCUzh2TTlCS0NQb3BTRHpYVURCSEVROXJpY3lZaEkzMVJ1WkplQlhVZEFzZ1ZfSTF4UGlSTUc4dXVFbHk0cEd3QUVGMGJZWFktSHZzdUZXWldMbE9BZFYxazg9In19XSwidHlwIjoiSldNLzEuMCJ9",
"tag":"2zOmsWc24FxmQGFAP6hM_g=="
}`


var errBadKeyHandleFormat = errors.New("bad key handle format")
const testMessage = "test message"

// Assert that Crypto implements the Crypto interface.
var _ crypto.Crypto = (*tinkcrypto.Crypto)(nil)

func TestNew(t *testing.T) {
	_, err := tinkcrypto.New()
	require.NoError(t, err)
}

func decryptWith_gojose(jweRaw string) (string, error) {
	jwe, err1 := gojose3.ParseEncrypted(jweRaw)
	if err1 != nil {
		return "", err1
	}
	bytes, err2 := jwe.Decrypt(gojose3.JSONWebKey{Algorithm: "PBES2-HS256+A128KW", Use: "A128CBC-HS256", KeyID: kid, Key: k})
	if err2 != nil {
		return "", err2
	}
	return string(bytes), nil
}

func TestCrypto_EncryptDecrypt(t *testing.T) {
	t.Run("test XChacha20Poly1305 encryption", func(t *testing.T) {
		/*
		signer := &CryptoSigner{
			crypto:      crypto,
			kh:          kh,
			PubKey:      string("pubKey"),
			PubKeyBytes: []byte(SignPairAPublicKeyB64ForTesting),
		}
		*/
		var keyManager KeyPairManager
		// It creates a new sender Keyset Handle (private + public key info) by a tink template
		myKeysetHandle, err := keyManager.CreateAuthcryptKeysetHandle()
		require.NoError(t, err)
		myPublicKeyBytes, err := keyManager.GetPublicKeyBytesByKeyset(myKeysetHandle)
		require.NoError(t, err)
		myPublicKID := base58.Encode(myPublicKeyBytes)

		// signer, err := newCryptoSigner(kmsapi.ED25519Type)
		// require.NoError(t, err)

		msg := []byte("test message")
		msgSig, err := signer.Sign(msg)
		require.NoError(t, err)

		pubKey := &sigverifier.PublicKey{
			Type: "JwsVerificationKey2020",
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{Key: []byte(SignPairAPublicKeyB64ForTesting)},	// signer.PublicKey()},
				Kty:        "OKP",
				Crv:        "Ed25519",
			},
		}
		v := jsonwebsignature2020.NewPublicKeyVerifier()

		err = v.Verify(pubKey, msg, msgSig)
		require.NoError(t, err)

		kh, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
		require.NoError(t, err)

		// tinkCrypto := tinkcrypto.Crypto{}
		c := tinkcrypto.Crypto{}
		// msg := []byte(testMessage)
		aad := []byte("some additional data")
		cipherText, nonce, err := c.Encrypt(msg, aad, kh)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.Equal(t, chacha.NonceSizeX, len(nonce))

		// decrypt with tinkcrypto.Decrypt
		plainText, err := c.Decrypt(cipherText, aad, nonce, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with gojose
		jwe, err := gojose3.ParseEncrypted(packedJWE)
		require.NoError(t, err)

		bytes, err := jwe.Decrypt(gojose3.JSONWebKey{
			Algorithm: EdDSA,	// Key algorithm, parsed from `alg` header.
			Use: "A128CBC-HS256",	// Key use, parsed from `use` header.
			KeyID: myPublicKID,		// Key identifier, parsed from `kid` header
			Key: myPublicKeyBytes,	// Cryptographic key, can be a symmetric or asymmetric key.
		})
		require.NoError(t, err)

		// json.Unmarshal(bytes, interface{})
		/*
		   let data = {
			   alg: senderKeys ? 'Authcrypt' : 'Anoncrypt',
			   enc: 'chacha20poly1305_ietf',
			   recipients: recipentsPublicSignVks,
			   typ: 'JWM/1.0',
		   }
		 */
	})

	t.Run("test AES256GCM encryption", func(t *testing.T) {
		kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
		require.NoError(t, err)

		c := tinkcrypto.Crypto{}
		msg := []byte(testMessage)
		aad := []byte("some additional data")
		cipherText, nonce, err := c.Encrypt(msg, aad, kh)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)
		require.Equal(t, aeadsubtle.AESGCMIVSize, len(nonce))

		// encrypt with nil key handle - should fail
		_, _, err = c.Encrypt(msg, aad, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		plainText, err := c.Decrypt(cipherText, aad, nonce, kh)
		require.NoError(t, err)
		require.Equal(t, msg, plainText)

		// decrypt with bad nonce - should fail
		plainText, err = c.Decrypt(cipherText, aad, []byte("bad nonce"), kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with bad cipher - should fail
		plainText, err = c.Decrypt([]byte("bad cipher"), aad, nonce, kh)
		require.Error(t, err)
		require.Empty(t, plainText)

		// decrypt with nil key handle - should fail
		_, err = c.Decrypt(cipherText, aad, nonce, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)
	})
}

func TestCrypto_SignVerify(t *testing.T) {
	t.Run("test with Ed25519 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := tinkcrypto.Crypto{}
		msg := []byte(testMessage)
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// sign with nil key handle - should fail
		_, err = c.Sign(msg, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		// sign with bad key handle - should fail
		_, err = c.Sign(msg, badKH)
		require.Error(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-256 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := tinkcrypto.Crypto{}
		msg := []byte(testMessage)
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)

		// verify with nil key handle - should fail
		err = c.Verify(s, msg, nil)
		require.Error(t, err)
		require.Equal(t, errBadKeyHandleFormat, err)

		// verify with bad key handle - should fail
		err = c.Verify(s, msg, badKH)
		require.Error(t, err)
	})
}

// X25519ECDHKWKeyTemplate is a KeyTemplate that generates a key that accepts a CEK for JWE content
// encryption. CEK wrapping is done outside of this Tink key (in the tinkcrypto service).
// Keys from this template represent a valid recipient public/private key pairs and can be stored in the KMS.The
// recipient key represented in this key template uses the following key wrapping curve:
//  - Curve25519

func TestCrypto_ECDH1PU_Wrap_Unwrap_X25519ECDHKWKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test with bad senderKH value
	_, err = c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender("badKey"))
	require.Error(t,err)
	fmt.Printf("error is OK: %v \n", err)

	// now test WrapKey with good key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUA256KWAlg)

	// test with valid wrappedKey, senderKH (public key) and recipientKey
	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKH))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	// extract sender public key and try Unwrap using extracted key
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)
	fmt.Printf("senderPubKey %v\n", senderPubKey)
	/*
	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	 */
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_X25519ECDHKWKey_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// extract sender public key as crypto.Public key to be used in WithSender()
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	// test WrapKey with extacted crypto.PublicKey above directly
	// WrapKey() only accepts senderKH as keyset.Handle because it will use its private key.
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUA256KWAlg)

	// UnwrapKey require sender public key used here or keyset.Handle which was tested in the previous function above
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	/*
	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	 */
}


// X25519ECDHXChachaKeyTemplateWithCEK is similar to X25519ECDHKWKeyTemplate but adding the cek to execute the
// CompositeEncrypt primitive for encrypting a message targeted to one ore more recipients.
// Keys from this template offer valid CompositeEncrypt primitive execution only and should not be stored in the KMS.
// The key created from this template has no recipient key info linked to it. It is exclusively used for primitive
// execution using content encryption algorithm:
//  - XChacha20Poly1305

//  TODO: not enough arguments in call to ecdh.X25519ECDHXChachaKeyTemplateWithCEK
//	have ()
//	want ([]byte)
/*
func TestCrypto_ECDH1PU_Wrap_Unwrap_X25519ECDHXChachaKeyTemplateWithCEK(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.X25519ECDHXChachaKeyTemplateWithCEK())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.X25519ECDHXChachaKeyTemplateWithCEK())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test with bad senderKH value
	_, err = c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender("badKey"))
	require.Error(t,err)
	fmt.Printf("error is OK: %v \n", err)

	// now test WrapKey with good key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUXC20PKWAlg)

	// test with valid wrappedKey, senderKH (public key) and recipientKey
	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKH))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	// extract sender public key and try Unwrap using extracted key
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)
	fmt.Printf("senderPubKey %v\n", senderPubKey)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_X25519ECDHXChachaKeyTemplateWithCEK_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.X25519ECDHXChachaKeyTemplateWithCEK())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.X25519ECDHXChachaKeyTemplateWithCEK())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// extract sender public key as crypto.Public key to be used in WithSender()
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	// test WrapKey with extacted crypto.PublicKey above directly
	// WrapKey() only accepts senderKH as keyset.Handle because it will use its private key.
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUXC20PKWAlg)

	// UnwrapKey require sender public key used here or keyset.Handle which was tested in the previous function above
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

 */

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// test with bad senderKH value
	_, err = c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender("badKey"))
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-1PU kek derivation: derive1PUKEK: EC key"+
		" derivation error derive1PUWithECKey: failed to retrieve sender key: ksToPrivateECDSAKey: bad key handle "+
		"format")

	// now test WrapKey with good key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUA256KWAlg)

	// test with valid wrappedKey, senderKH (public key) and recipientKey
	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKH))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	// extract sender public key and try Unwrap using extracted key
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	apu := random.GetRandomBytes(uint32(10)) // or sender name
	apv := random.GetRandomBytes(uint32(10)) // or recipient name

	// extract sender public key as crypto.Public key to be used in WithSender()
	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	// test WrapKey with extacted crypto.PublicKey above directly
	// WrapKey() only accepts senderKH as keyset.Handle because it will use its private key.
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, crypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.EqualValues(t, wrappedKey.APU, apu)
	require.EqualValues(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, tinkcrypto.ECDH1PUA256KWAlg)

	// UnwrapKey require sender public key used here or keyset.Handle which was tested in the previous function above
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)

	crv, err := hybrid.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, crypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, uCEK)
}


// Package Aries tinkcrypto includes the default implementation of pkg/crypto. It uses Tink for executing crypto primitives
// New creates a new Crypto instance.
// Encrypt will encrypt msg using the implementation's corresponding encryption key and primitive in kh of a public key.
// Decrypt will decrypt cipher using the implementation's corresponding encryption key referenced by kh of a private key.
// Sign will sign msg using the implementation's corresponding signing key referenced by kh of a private key.
// Verify will verify sig signature of msg using the implementation's corresponding signing key referenced by kh of a public key.

// Package ecdh1pu provides implementations of payload encryption using ECDH-1PU KW key wrapping with AEAD primitives.
// The functionality of ecdh1pu Encryption is represented as a pair of primitives (interfaces):
// - ECDH1PUEncrypt for encryption of data and aad for a given list of recipients keys
// - ECDH1PUDecrypt for decryption of data for a certain recipient key and returning decrypted plaintext
// e.g. authcryptTemplate := ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate()

// WrapKey will do ECDH (ES or 1PU) key wrapping of cek using apu, apv and recipient public key 'recPubKey'.
// The optional 'wrapKeyOpts' specifies the sender kh for 1PU key wrapping.
// This function is used with the following parameters:
//  - Key Wrapping: ECDH-ES (no options)/ECDH-1PU (using crypto.WithSender() option) over A256KW as
// 		per https://tools.ietf.org/html/rfc7518#appendix-A.2
//  - KDF: Concat KDF as per https://tools.ietf.org/html/rfc7518#section-4.6
// returns the resulting key wrapping info as *composite.RecipientWrappedKey or error in case of wrapping failure.

// UnwrapKey unwraps a key in recWK using ECDH (ES or 1PU) with recipient private key kh.
// The optional 'wrapKeyOpts' specifies the sender kh for 1PU key unwrapping.
// Note, if the option was used in WrapKey(), then it must be set here as well for a successful unwrapping.
// This function is used with the following parameters:
//  - Key Unwrapping: ECDH-ES (no options)/ECDH-1PU (using crypto.WithSender() option) over A256KW as
// 		per https://tools.ietf.org/html/rfc7518#appendix-A.2
//  - KDF: Concat KDF as per https://tools.ietf.org/html/rfc7518#section-4.6
// returns the resulting unwrapping key or error in case of unwrapping failure.

const SignPairAPublicKeyB64ForTesting = "2YhcRXHiVZOvv3mi7SGGa07uWoYXY2PQw0goVC8J2NA="
const SignPairAPrivateKeyB64ForTesting = "tBvECZoHpH14h3s9tcBzHwIW62uAvWK4P813xvSzQjjZiFxFceJVk6+/eaLtIYZrTu5ahhdjY9DDSChULwnY0A=="

const SignPairBPublicKeyForB64ForTesting = "rDV054mpjozb9OFK9mVBgB9EBgtEnocs9BiOVRjykDc="
const SignPairBPrivateKeyB64ForTesting = "Z+UiZnUTQwWYLD5T904auTSKLAsCZjpm9gfYhc+ScPWsNXTniamOjNv04Ur2ZUGAH0QGC0Sehyz0GI5VGPKQNw=="

const PackedJWEForTesting = `{"ciphertext":"q_b3MnNDXQQ556y6pYi-wGdSVCY=","iv":"krWu9YLIW5ZcfVoQ","protected":"eyJhbGciOiJBdXRoY3J5cHQiLCJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJyZWNpcGllbnRzIjpbeyJlbmNyeXB0ZWRfa2V5IjoiM1dRY2JnSjBYSm9iWlVDUWF3Rk8zenp0MFVwNDlOZzhIMUx4QnJDa3ZJOVQ2bzZqOTVxcmxmM3gtcXBkZjV1eCIsImhlYWRlciI6eyJpdiI6ImozVENDc2NVTldwNEc1Q2Ruc1ItUVYzOWMxSTJHOXpnIiwia2lkIjoiQlBNbjhQWFB1b29ndTlLbzE4c0pKWHN3MmVhMmVMRmRNZ2RCZ2taaWJBTFgiLCJzZW5kZXIiOiJhYzYwdjJVV1ZaUUJSQXRLUy1uX2YwQ21nOU1JeGFld0MtdXRUdVNQSlNVSUNRVnNXWFZPaUFyU3dBTF82MVdPYWRfcll0RWtWSTAwTWxmX3RENTRtYm1NeTFVVnV1c0NkOWN1TjBUZkZfRnpjUnBZaFF0bkZoZ0dlVzA9In19XSwidHlwIjoiSldNLzEuMCJ9","tag":"Y2ac6u0nn8CcBv3fRSLgtg=="}`
// JweDataForTesting = { data: 'some data' }

const SodiumPrivateKeyB64ForTesting = "Kr3yyCb5CT/WkOzI4ZdyPrwlK95LLWYdOmkmIaQwYTyaTyQRR6PItBsyNoGWdi5Qt+E2KnK7snfC0Cv5rlZT0A=="
const SodiumPublicKeyB64ForTesting = "mk8kEUejyLQbMjaBlnYuULfhNipyu7J3wtAr+a5WU9A="
const UnpackedJWEForTesting =  `{ message: '{"data":"some data"}',
      recipientKey: 'BPMn8PXPuoogu9Ko18sJJXsw2ea2eLFdMgdBgkZibALX',
      senderKey: 'BPMn8PXPuoogu9Ko18sJJXsw2ea2eLFdMgdBgkZibALX',
      nonRepudiableVerification: false }`

func PublicKeyToKeysetHandle() {
}

// FAILS Pack message with DID with error "failed to convert recipient keys"
/*
func Test_PackMessage(t *testing.T) {
	payloadBytes := []byte("test")
	fromKeyBytes, _ := Base64StringToBytes(SignPairAPrivateKeyB64ForTesting)
	toKeyBytes, _ := Base64StringToBytes(SignPairBPublicKeyForB64ForTesting)

	// Packing with 'Envelope'
	messageEnvelope := &transport.Envelope{
		Message: payloadBytes,
		FromKey: fromKeyBytes,
		ToKeys:  []string{base58.Encode(toKeyBytes)},	// base58 public keys for an outbound message packing
		ToKey:   toKeyBytes,	// ToKey holds the key that was used to decrypt an inbound message
		FromDID: "did:test:sender",
		ToDID:   "did:test:receiver",
	}

	jwEncryptedBytes, err := PackMessage(messageEnvelope) // failed to pack: authcrypt Pack: failed to convert recipient keys: invalid character '¬' looking for beginning of value
	require.NoError(t, err)
	fmt.Printf("Unpacked Message = %v \n", jwEncryptedBytes)

	// only for testing
	// authcryptPacker := &authcrypt.Packer{}
	// jwEncrypted, err := authcryptPacker.Pack(payloadBytes, senderIdBytes, recipientsPubKeyBytes)
	// require.NoError(t, err)

	// jwe, err := UnpackMessage(jwEncrypted)
	// require.NoError(t, err)
}
*/


/* From package common_go_proto

type EllipticCurveType int32

const (
	EllipticCurveType_UNKNOWN_CURVE EllipticCurveType = 0
	EllipticCurveType_NIST_P256     EllipticCurveType = 2
	EllipticCurveType_NIST_P384     EllipticCurveType = 3
	EllipticCurveType_NIST_P521     EllipticCurveType = 4
	EllipticCurveType_CURVE25519    EllipticCurveType = 5
)

var EllipticCurveType_name = map[int32]string{
	0: "UNKNOWN_CURVE",
	2: "NIST_P256",
	3: "NIST_P384",
	4: "NIST_P521",
	5: "CURVE25519",
}

var EllipticCurveType_value = map[string]int32{
	"UNKNOWN_CURVE": 0,
	"NIST_P256":     2,
	"NIST_P384":     3,
	"NIST_P521":     4,
	"CURVE25519":    5,
}
 */

/* Aries RFC 0334: JWE envelope 1.0: https://github.com/hyperledger/aries-rfcs/blob/master/features/0334-jwe-envelope/README.md#authcrypt-using-ecdh-1pu-key-wrapping-mode
	Authcrypt Key Encryption: ECDH-1PU + AES key wrap
	Authcrypt Encryption algorithm identifier: ECDH-1PU+A256KW
	The following curves are supported:
	- Curve Name: X25519 (aka Curve25519) - Curve identifier: X25519 (default)
	- Curve Name: NIST P256 (aka SECG secp256r1 and ANSI X9.62 prime256v1, ref here) - Curve identifier: P-256

ECDH uses a curve; most software use the standard NIST curve P-256.
Curve25519 is another curve, whose "sales pitch" is that it is faster, not stronger, than P-256.
Signature algorithm based on elliptic curves: ECDSA or Ed25519; that's ECDSA for P-256, Ed25519 for Curve25519.
Using P-256 should yield better interoperability right now, because Ed25519 is much newer and not as widespread.
According to DJB's safecurves.cr.yp.to website, the NIST curve may not be as safe or foolproof as the Curve25519.

Authcrypt using ECDH-1PU key wrapping mode

{
    "protected": base64url({
        "typ": "didcomm-envelope-enc",
        "enc": "A256GCM", // or "XC20P"
        "skid": base64url(sender KID),
    }),
    "recipients": [
        {
            "encrypted_key": "base64url(encrypted CEK)",
            "header": {
                "kid": base64url(recipient KID),
                "alg": "ECDH-1PU+A256KW",
                "enc": "A256GCM",
                "apu": base64url(senderID),
                "apv": base64url(recipientID),
                "epk": {
                  "kty": "OKP",
                  "crv": "X25519",
                  "x": "aOH-76BRwkHf0nbGokaBsO6shW9McEs6jqVXaF0GNn4"
                },
            }
        },
       ...
    ],
    "aad": "base64url(sha256(concat('.',sort([recipients[0].kid, ..., recipients[n].kid])))))",
    "iv": "base64url(content encryption IV)",
    "ciphertext": "base64url(XC20P(DIDComm payload, base64Url(json($protected)+'.'+$aad), content encryption IV, CEK))"
    "tag": "base64url(AEAD Authentication Tag)"
*/

// ----------- from Aries 0.1.4 -------------
/*
func TestJWEEncryptRoundTrip(t *testing.T) {
	_, err := ariesjose.NewJWEEncrypt("", "", "", nil, nil)
	require.EqualError(t, err, "empty recipientsPubKeys list",
		"NewJWEEncrypt should fail with empty recipientPubKeys")

	recECKeys, recKHs := createRecipients(t, 20)

	_, err = ariesjose.NewJWEEncrypt("", "", "", nil, recECKeys)
	require.EqualError(t, err, "encryption algorithm '' not supported",
		"NewJWEEncrypt should fail with empty encAlg")

	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	// try to deserialize with go-jose (can't decrypt in go-jose since private key is protected by Tink)
	joseJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)
	require.NotEmpty(t, joseJWE)

	// try to deserialize with local package
	localJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	// t.Run("Decrypting JWE tests failures", func(t *testing.T) {}

	for _, recKH := range recKHs {
		recipientKH := recKH

		t.Run("Decrypting JWE test success ", func(t *testing.T) {
			jweDecrypter := ariesjose.NewJWEDecrypt(nil, recipientKH)	// it changes in Aries 0.1.5

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

func TestJWEEncryptRoundTripWithSingleRecipient(t *testing.T) {
	recECKeys, recKHs := createRecipients(t, 1)

	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, cryptoapi.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.Encrypt(pt)
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.CompactSerialize(json.Marshal)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)

	// try to deserialize with local package
	localJWE, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	jweDecrypter := ariesjose.NewJWEDecrypt(nil, recKHs[0])

	var msg []byte

	msg, err = jweDecrypter.Decrypt(localJWE)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecrypt(t *testing.T) {
	// get two generated recipient Tink keys
	recECKeys, _ := createRecipients(t, 2)
	// create a normal recipient key (not using Tink)
	rec3PrivKey, err := ecdsa.GenerateKey(subtle.GetCurve(recECKeys[0].Curve), rand.Reader)
	require.NoError(t, err)

	// add third key to recECKeys
	recECKeys = append(recECKeys, &composite.PublicKey{
		X:     rec3PrivKey.PublicKey.X.Bytes(),
		Y:     rec3PrivKey.PublicKey.Y.Bytes(),
		Curve: rec3PrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// encrypt using local jose package
	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	// now parse serializedJWE using go-jose
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// Decrypt with third recipient's private key (non Tink key)
	i, _, msg, err := gjParsedJWE.DecryptMulti(rec3PrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)

	// the third recipient's index is 2
	require.Equal(t, 2, i)
}

func TestInteropWithGoJoseEncryptAndLocalJoseDecrypt(t *testing.T) {
	recECKeys, recKHs := createRecipients(t, 3)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewMultiEncrypter(jose.A256GCM, gjRecipients,
		eo.WithType("didcomm-envelope-enc"))
	require.NoError(t, err)

	pt := []byte("Test secret message")
	aad := []byte("Test some auth data")

	// encrypt pt using go-jose encryption
	gjJWEEncrypter, err := gjEncrypter.EncryptWithAuthData(pt, aad)
	require.NoError(t, err)

	// get go-jose serialized JWE
	gjSerializedJWE := gjJWEEncrypter.FullSerialize()

	// deserialize using local jose package
	localJWE, err := ariesjose.Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	for i, recKH := range recKHs {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message encrypted by go-jose test success", i), func(t *testing.T) {
			jweDecrypter := ariesjose.NewJWEDecrypt(nil, recipientKH)

			var msg []byte

			msg, err = jweDecrypter.Decrypt(localJWE)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg)
		})
	}
}

func convertToGoJoseRecipients(t *testing.T, keys []*cryptoapi.PublicKey) []jose.Recipient {
	t.Helper()

	var joseRecipients []jose.Recipient

	for _, key := range keys {
		c := subtle.GetCurve(key.Curve)
		gjKey := jose.Recipient{
			Algorithm: jose.ECDH_ES_A256KW,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(key.X),
				Y:     new(big.Int).SetBytes(key.Y),
			},
		}

		joseRecipients = append(joseRecipients, gjKey)
	}

	return joseRecipients
}
*/
func TestCrypto_SignVerify_014(t *testing.T) {
	t.Run("test with Ed25519 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := tinkcrypto.Crypto{}
		msg := []byte("testMessage")
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// sign with bad key handle - should fail
		_, err = c.Sign(msg, badKH)
		require.Error(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-256 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("babdUrl", nil))
		require.NoError(t, err)

		c := tinkcrypto.Crypto{}
		msg := []byte("testMessage")
		s, err := c.Sign(msg, kh)
		require.NoError(t, err)

		// get corresponding public key handle to verify
		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(s, msg, pubKH)
		require.NoError(t, err)

		// verify with bad key handle - should fail
		err = c.Verify(s, msg, badKH)
		require.Error(t, err)
	})
}

// ---------------------------------------


// --- other tests but for Aries 0.1.5 ---

// Anoncrypt: ECDH-ES key wrapping mode and A256GCM content encryption
// "Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static" (ECDH-ES) X25519
// The sender computes the shared key using it as a direct encryption AES256-GCM key

/* some notes
Encrypt a JWE token::
key = jwk.JWK.generate(kty='oct', size=256)
payload = "My Encrypted message"
jwetoken = jwe.JWE(payload.encode('utf-8'),

json_encode({"alg": "A256KW","enc": "A256CBC-HS512"}))
jwetoken.add_recipient(key)
enc = jwetoken.serialize()

Decrypt a JWE token::
jwetoken = jwe.JWE()
jwetoken.deserialize(enc)
jwetoken.decrypt(key)
payload = jwetoken.payload
*/
