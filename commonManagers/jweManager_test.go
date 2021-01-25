package commonManagers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/google/tink/go/aead"
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	ariesjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

/* https://github.com/google/tink/blob/master/docs/KEY-MANAGEMENT.md
Tink provides support for key management features like key versioning, key rotation, and storing keysets
	or encrypting with master keys in remote key management systems (KMS).

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

// Package tinkcrypto includes the default implementation of pkg/crypto. It uses Tink for executing crypto primitives
// New creates a new Crypto instance.
// Encrypt will encrypt msg using the implementation's corresponding encryption key and primitive in kh of a public key.
// Decrypt will decrypt cipher using the implementation's corresponding encryption key referenced by kh of a private key.
// Sign will sign msg using the implementation's corresponding signing key referenced by kh of a private key.
// Verify will verify sig signature of msg using the implementation's corresponding signing key referenced by kh of a public key.

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

/*
func Test_PackMessage(t *testing.T) {
	payloadBytes := []byte("test")
	fromKeyBytes, _ := Base64StringToBytes(SignPairAPublicKeyB64ForTesting)
	toKeyBytes, _ := Base64StringToBytes(SignPairBPublicKeyForB64ForTesting)

	// Packing with 'Envelope'
	messageEnvelope := &transport.Envelope{
		Message: payloadBytes,
		FromKey: fromKeyBytes,
		// ToKeys:  []string{"key1", "key2"},	// ToKeys stores keys for an outbound message packing
		ToKey:   toKeyBytes,	// ToKey holds the key that was used to decrypt an inbound message
		FromDID: "",
		ToDID:   "",
	}

	jwEncryptedBytes, err := PackMessage(messageEnvelope)
	require.NoError(t, err)
	fmt.Printf("Unpacked Message = %v \n", jwEncryptedBytes)

	// only for testing
	// authcryptPacker := &authcrypt.Packer{}
	// jwEncrypted, err := authcryptPacker.Pack(payloadBytes, senderIdBytes, recipientsPubKeyBytes)
	// require.NoError(t, err)

	// jwe, err := UnpackMessage(jwEncrypted)
	// require.NoError(t, err)
}

func Test_UnpackMessage(t *testing.T) {
	// UnpackMessage
}

// Aries RFC 0334: JWE envelope 1.0: https://github.com/hyperledger/aries-rfcs/blob/master/features/0334-jwe-envelope/README.md#authcrypt-using-ecdh-1pu-key-wrapping-mode
// Authcrypt: ECDH-1PU key wrapping mode to encrypt for a given list of recipients keys
func Test_ECDH1PU(t *testing.T) {
	var keyManager KeyPairManager
	// It creates a new sender
	senderPublicKH, err := keyManager.CreateAuthcryptKeysetHandle()
	require.NoError(t, err)

	// It creates a new recipient
	// recipientCompositePublicKeys, recKHs := createECDHEntities(t, 2, false)
	recipientPublicKH, err := keyManager.CreateAuthcryptKeysetHandle()
	require.NoError(t, err)
	recipientCompositePublicKey, err := keyManager.GetCompositePublicKey(recipientPublicKH)
	require.NoError(t, err)

	// It creates an array of publicKeys of recipients to encrypt for
	var recipientCompositePublicKeys []*composite.PublicKey
	recipientCompositePublicKeys = append(recipientCompositePublicKeys, recipientCompositePublicKey)

	// It creates an array of Handlers only for testing an array of recipients
	var recipientsPublicKeyHandlers []*keyset.Handle
	recipientsPublicKeyHandlers = append(recipientsPublicKeyHandlers, recipientPublicKH)

	// It creates the JWE message
	mockSenderID := "1234"
	jweEnc, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, composite.DIDCommEncType, mockSenderID, senderPublicKH, recipientCompositePublicKeys)
	require.NoError(t, err)
	require.NotEmpty(t, jweEnc)

	// It encrypts the JWE message: ECDH1PU / authcrypt
	pt := []byte("plaintext payload")
	jwEncrypted, err := jweEnc.Encrypt(pt)
	require.NoError(t, err)

	// It serializes the encrypted JWE message to be sent
	var serializedJWE string
	if len(recipientCompositePublicKeys) == 1 {
		serializedJWE, err = jwEncrypted.CompactSerialize(json.Marshal)
	} else {
		serializedJWE, err = jwEncrypted.FullSerialize(json.Marshal)
	}
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWE)
	fmt.Printf("Serialized JWE = %v \n", serializedJWE)

	// Now it deserializes the received message
	jweReceived, err := ariesjose.Deserialize(serializedJWE)
	require.NoError(t, err)

	// Test ECDH-1PU decrypt for every recipient
	for i, recKH := range recipientsPublicKeyHandlers {
		recipientKH := recKH

		t.Run(fmt.Sprintf("%d: Decrypting JWE message test success", i), func(t *testing.T) {
			jd := ariesjose.NewJWEDecrypt(nil, recipientKH)
			require.NotEmpty(t, jd)

			var msg []byte

			msg, err = jd.Decrypt(jweReceived)
			require.NoError(t, err)
			require.EqualValues(t, pt, msg) // jwedecrypt: failed to add sender key: unable to decrypt JWE with 'skid' header, third party key store is nil

		})
	}
}

*/
// ----------- from Aries 0.1.4 -------------
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

	jweEncrypter, err := ariesjose.NewJWEEncrypt(ariesjose.A256GCM, composite.DIDCommEncType, "", nil, recECKeys)
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

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, numberOfEntities int) ([]*composite.PublicKey, []*keyset.Handle) {
	return createECDHEntities(t, numberOfEntities, true)
}

func createECDHEntities(t *testing.T, numberOfEntities int, isECDHES bool) ([]*composite.PublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []*composite.PublicKey
		rKH []*keyset.Handle	// keyset.Handle from github.com/google/tink/go/keyset
	)

	for i := 0; i < numberOfEntities; i++ {
		mrKey, kh := createAndMarshalEntityKey(t, isECDHES)	// keyset.Handle from github.com/google/tink/go/keyset
		ecPubKey := new(composite.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		r = append(r, ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createAndMarshalEntityKey creates a new recipient keyset.Handle (github.com/google/tink/go/keyset),
// extracts public key, marshals it and returns both marshalled public key and original recipient keyset.Handle.
func createAndMarshalEntityKey(t *testing.T, isECDHES bool) ([]byte, *keyset.Handle) { // keyset.Handle from github.com/google/tink/go/keyset
	t.Helper()

	tmpl := ecdhes.ECDHES256KWAES256GCMKeyTemplate()	// Anonymcrypt (no ECDH1PU)

	if !isECDHES {
		tmpl = ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate()	// Authcrypt (ECDH1PU)
	}

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	return buf.Bytes(), kh
}

func convertToGoJoseRecipients(t *testing.T, keys []*composite.PublicKey) []jose.Recipient {
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

func TestCrypto_SignVerify(t *testing.T) {
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

func TestCrypto_ECDHES_Wrap_Unwrap_Key(t *testing.T) {}	// its for Aries 0.1.5

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key(t *testing.T) {} // its for Aries 0.1.5

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key_Using_CryptoPubKey_as_SenderKey(t *testing.T) {} // its for Aries 0.1.5

func Test_EncryptionAES256GCM(t *testing.T) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	c := tinkcrypto.Crypto{}
	msg := []byte("testMessage")
	aad := []byte("some additional data")
	cipherText, nonce, err := c.Encrypt(msg, aad, kh)
	require.NoError(t, err)
	require.NotEmpty(t, nonce)
	require.Equal(t, aeadsubtle.AESGCMIVSize, len(nonce))

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
}

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
