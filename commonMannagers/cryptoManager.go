package managers

import (
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type CryptoManager struct {
}



func (manager *CryptoManager) GenerateKeyPair() (publicKeyBase64 string, privateKeyBase64 string, err error) {
	publicKeyBytes, privateKeysBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return BytesToBase64String(publicKeyBytes[:]), BytesToBase64String(privateKeysBytes[:]), nil
}

func stringToBytes32 (str string) ([32]byte){
	n := []byte(str)
	var bytes [32]byte
	copy(bytes[:], n)
	return bytes
}

func BytesToBase64String(b []byte) string {
	return b64.StdEncoding.EncodeToString(b)
}

func Base64StringToBytes(str string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(str)
}

func base64StringToBytes32(str string) ([32]byte, error) {
	b, err:= b64.StdEncoding.DecodeString(str)
	var bytes [32]byte
	copy(bytes[:], b)
	return bytes, err
}

func bytesToString (b []byte) string {
	return string(b[:])
}

func (manager *CryptoManager) EncryptUsingEncryptionKey(encryptionKey *models.EncryptionKey, encryptionRequest *models.EncryptionRequest) (encryptionResult *models.EncryptedResult, err error) {
	encryptionResult = &models.EncryptedResult{}

	encryptedMessage, err := manager.EncryptMessage(encryptionRequest.OtherPartPublicKeyBase64, encryptionKey.PrivateKeyBase64, encryptionRequest.Payload)
	if err != nil {
		return nil, err
	}
	encryptionResult.EncryptedMessageBase64 = encryptedMessage
	return encryptionResult, nil
}

func (manager *CryptoManager) EncryptMessage(recipientPublicKey, senderPrivateKey, message string) (encryptedMessageBase64 string, err error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	msg := []byte(message)
	recipientPublicKeyBytes, err1 := base64StringToBytes32(recipientPublicKey)
	senderPrivateKeyBytes, err2 := base64StringToBytes32(senderPrivateKey)

	if err1 != nil || err2 != nil {
		return "", errors.New("error converting to base 64")
	}

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &recipientPublicKeyBytes,&senderPrivateKeyBytes)

	encrypted := box.SealAfterPrecomputation(nonce[:],  msg, &nonce, &sharedKey)
	//encrypted := box.Seal(nonce[:], msg, &nonce, &recipientPublicKeyBytes, &senderPrivateKeyBytes)
	return BytesToBase64String(encrypted), nil
}

func (manager *CryptoManager) DecryptUsingEncryptionKey(encryptionKey *models.EncryptionKey, decryptionRequest *models.DecryptionRequest) (decryptionResult *models.DecryptedResult, err error) {
	decryptionResult = &models.DecryptedResult{}

	decryptedMessage, err := manager.DecryptMessage(decryptionRequest.OtherPartPublicKeyBase64, encryptionKey.PrivateKeyBase64, decryptionRequest.Payload)
	if err != nil {
		return nil, err
	}
	decryptionResult.DecryptedMessage = decryptedMessage
	return decryptionResult, nil
}

func (manager *CryptoManager) DecryptMessage(senderPublicKeyBase64, recipientPrivateKeyBase64, encryptedMessageBase64 string) (decryptedMessage string, err error) {

	encryptedMessageBytes, err := Base64StringToBytes(encryptedMessageBase64)
	recipientPrivateKeyBytes,  err1 := base64StringToBytes32(recipientPrivateKeyBase64)
	senderPublicKeyBytes , err2 := base64StringToBytes32(senderPublicKeyBase64)

	if err != nil || err1 != nil || err2 != nil {
		return "", errors.New("error converting to base 64")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encryptedMessageBytes[:24])

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &senderPublicKeyBytes,&recipientPrivateKeyBytes)

	decrypted, ok :=box.OpenAfterPrecomputation(nil, encryptedMessageBytes[24:], &decryptNonce, &sharedKey)

	//decrypted, ok := box.Open(nil, encryptedMessageBytes[24:], &decryptNonce, &senderPublicKeyBytes, &recipientPrivateKeyBytes)
	if !ok {
		return "", errors.New("error decrypting")
	}
	return bytesToString(decrypted), nil
}

func (manager *CryptoManager) GetSharedEncryptionKey (recipientPublicKey, senderPrivateKey string) (sharedKey64String string, err error) {

	recipientPublicKeyBytes, err1 := base64StringToBytes32(recipientPublicKey)
	senderPrivateKeyBytes, err2 := base64StringToBytes32(senderPrivateKey)

	if err1 != nil || err2 != nil {
		return "", errors.New("error converting to base 64")
	}

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &recipientPublicKeyBytes,&senderPrivateKeyBytes)

	return BytesToBase64String(sharedKey[:]), nil
}