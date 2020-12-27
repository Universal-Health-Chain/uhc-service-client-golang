package commonManagers

import (
	"crypto/rand"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
	"log"
	"testing"
)

var encryptionManager = CryptoManager{}
var encryptionKeys,_ = utils.GetEncryptionKeysForTesting()

func TestEncryptionManager_StringByte(t *testing.T) {
	publicKeyBytes, _, _ := box.GenerateKey(rand.Reader)
	str := BytesToBase64String(publicKeyBytes[:])

	bytes, _:= base64StringToBytes32(str)

	assert.Equal(t, *publicKeyBytes, bytes)
}

func TestCryptoManager_EncryptUsingEncryptionKey_Decrypt(t *testing.T) {
	keySender := encryptionKeys[0]
	public, private, _ := encryptionManager.GenerateKeyPair()
	keySender.PublicKeyBase64 = public
	keySender.PrivateKeyBase64 = private

	keyReciever := encryptionKeys[0]
	publicReciever, privateReciever, _ := encryptionManager.GenerateKeyPair()
	keyReciever.PublicKeyBase64 = publicReciever
	keyReciever.PrivateKeyBase64 = privateReciever

	message := "hello world"

	encryptionRequest := models.EncryptionRequest{}
	encryptionRequest.OtherPartPublicKeyBase64 = keyReciever.PublicKeyBase64
	encryptionRequest.Payload = message

	encryptionResult, err := encryptionManager.EncryptUsingEncryptionKey(&keySender,&encryptionRequest)

	assert.NotEqual(t, encryptionResult, nil)
	assert.Equal(t, err, nil)

	decryptionRequest := models.DecryptionRequest{}
	decryptionRequest.Payload = encryptionResult.EncryptedMessageBase64
	decryptionRequest.OtherPartPublicKeyBase64 =  keySender.PublicKeyBase64

	decryptionResult, err := encryptionManager.DecryptUsingEncryptionKey(&keyReciever, &decryptionRequest)
	assert.NotEqual(t, decryptionResult, nil)
	assert.Equal(t, err, nil)

	assert.Equal(t, decryptionResult.DecryptedMessage, message)

}

func TestEncryptionManager_Decrypt(t *testing.T) {
	message := "Hello world"

	senderPublicKey, senderPrivateKey, _ := encryptionManager.GenerateKeyPair()
	recipientPublicKey, recipientPrivateKey, _ := encryptionManager.GenerateKeyPair()

	// real flow using each others keys
	encrypted,err1 := encryptionManager.EncryptMessage(recipientPublicKey,senderPrivateKey, message)
	assert.Equal(t, err1, nil)

	log.Println("decrypting using recipient private key")
	decrypted,err2 := encryptionManager.DecryptMessage(senderPublicKey, recipientPrivateKey, encrypted)
	assert.Equal(t, err2, nil)
	assert.Equal(t, decrypted, message)

	log.Println("decrypting using same keys used for encryptation")
	decrypted2,err3 := encryptionManager.DecryptMessage(recipientPublicKey,senderPrivateKey, encrypted)
	assert.Equal(t, err3, nil)
	assert.Equal(t, decrypted2, message)

}

func TestCryptoManager_GetSharedEncryptionKey(t *testing.T) {
	keySender := encryptionKeys[0]
	public, private, _ := encryptionManager.GenerateKeyPair()
	keySender.PublicKeyBase64 = public
	keySender.PrivateKeyBase64 = private

	keyRecipient := encryptionKeys[0]
	publicRecipient, privateRecipient, _ := encryptionManager.GenerateKeyPair()
	keyRecipient.PublicKeyBase64 = publicRecipient
	keyRecipient.PrivateKeyBase64 = privateRecipient

	encryptionRequest := models.EncryptionRequest{}
	encryptionRequest.OtherPartPublicKeyBase64 = keyRecipient.PublicKeyBase64

	sharedKeyResult, err := encryptionManager.GetSharedEncryptionKey(publicRecipient,private)

	assert.NotEqual(t, sharedKeyResult, nil)
	assert.Equal(t, err, nil)

	MySecretKeyForTesting := "lFO8hOSodEKssy6fezSpH6IPBtRoPVFPizoDkOvZcnw="
	TheirPublicKeyForTesting := "17Ibb48t+Qs2e+S1s6o5YIdE6xY/sF5BefXxzut5Wn0="
	ConnectionSharedKeyForTesting :=  "okH9Y2fFD0I6pfZliinOpZ+rEV7/bWW92wdUMuV8iC4=" // "dyn2O2sdUqnMvpxTySya2JHww+48keyQD9RoGrXEtY0="

	sharedKeyResult, err = encryptionManager.GetSharedEncryptionKey(TheirPublicKeyForTesting, MySecretKeyForTesting)

	assert.Equal(t, sharedKeyResult, ConnectionSharedKeyForTesting)
}

func TestCryptoManager_EncryptBytesWithSharedKey(t *testing.T) {
	keySender := encryptionKeys[0]
	public, private, _ := encryptionManager.GenerateKeyPair()
	keySender.PublicKeyBase64 = public
	keySender.PrivateKeyBase64 = private

	keyRecipient := encryptionKeys[0]
	publicRecipient, privateRecipient, _ := encryptionManager.GenerateKeyPair()
	keyRecipient.PublicKeyBase64 = publicRecipient
	keyRecipient.PrivateKeyBase64 = privateRecipient

	sharedKeyResult, err := encryptionManager.GetSharedEncryptionKey(publicRecipient, private)

	message:="message test"

	resultEncrypted, err:= encryptionManager.EncryptToBase64WithSharedKeyInBase64(&message, &sharedKeyResult)

	assert.NotEqual(t, resultEncrypted, nil)
	assert.Equal(t, err, nil)

	resultDecrypted, err:= encryptionManager.DecryptBase64WithSharedKeyInBase64(&resultEncrypted, &sharedKeyResult)

	assert.NotEqual(t, resultDecrypted, nil)
	assert.Equal(t, err, nil)
	assert.Equal(t, message, resultDecrypted)


}