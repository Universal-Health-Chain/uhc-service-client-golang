package commonManagers

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
	return GenerateKeyPair()
}

func GenerateKeyPair() (publicKeyBase64 string, privateKeyBase64 string, err error) {
	publicKeyBytes, privateKeysBytes, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return BytesToBase64String(publicKeyBytes[:]), BytesToBase64String(privateKeysBytes[:]), nil
}

func BytesToBase64String(b []byte) string {
	return b64.StdEncoding.EncodeToString(b)
}

func Base64StringToBytes(str string) ([]byte, error) {
	return b64.StdEncoding.DecodeString(str)
}

func BytesToStringUTF8(b []byte) string {
	return string(b[:])
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

func (manager *CryptoManager) EncryptUsingEncryptionKey(encryptionKey *models.Key, encryptionRequest *models.EncryptionRequest) (encryptionResult *models.EncryptedResult, err error) {
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

func (manager *CryptoManager) DecryptUsingEncryptionKey(encryptionKey *models.Key, decryptionRequest *models.DecryptionRequest) (decryptionResult *models.DecryptedResult, err error) {
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


func (manager *CryptoManager) GetSharedKeyInBytesByBase64Keys(recipientPublicKey, senderSecretKey *string) (sharedKey [32]byte, err error){
	var sharedKeyBytes [32]byte
	recipientPublicKeyBytes, err := base64StringToBytes32(*recipientPublicKey)
	if err != nil {return sharedKeyBytes, err}	// empty and error
	senderPrivateKeyBytes, err := base64StringToBytes32(*senderSecretKey)
	if err != nil {return sharedKeyBytes, err}	// empty and error
	box.Precompute(&sharedKeyBytes, &recipientPublicKeyBytes, &senderPrivateKeyBytes)
	return sharedKeyBytes, nil
}




func (manager *CryptoManager) EncryptToBase64WithSharedKeyInBase64(message, sharedKey *string) (encryptedMessage string, err error) {
	messageBytes := []byte(*message)
	sharedKeyBytes, err := base64StringToBytes32(*sharedKey)
	if err != nil {
		return "", err
	}

	encryptedBytes,err := manager.EncryptBytesWithSharedKey(&messageBytes, &sharedKeyBytes)
	return BytesToBase64String(encryptedBytes), err
}

func (manager *CryptoManager) EncryptBytesWithSharedKey(messageBytes *[]byte, sharedKeyBytes *[32]byte) (encryptedMessage []byte, err error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encryptedBytes := box.SealAfterPrecomputation(nonce[:], *messageBytes, &nonce, sharedKeyBytes)
	return encryptedBytes, err	// nonce error
}

func (manager *CryptoManager) EncryptToStringUTF8(recipientPublicKey, senderSecretKey, message string) (encryptedMessage string, err error) {
	sharedKeyBytes, _ := manager.GetSharedKeyInBytesByBase64Keys(&recipientPublicKey, &senderSecretKey)
	messageBytes := []byte(message)
	encryptedBytes, err := manager.EncryptBytesWithSharedKey(&messageBytes, &sharedKeyBytes)
	return BytesToStringUTF8(encryptedBytes), err
}

func (manager *CryptoManager) DecryptBase64WithSharedKeyInBase64(encryptedMessage, sharedKey *string) (decryptedMessage string, err error) {
	encryptedMessageBytes, _ := Base64StringToBytes(*encryptedMessage)
	sharedKeyBytes, _ := base64StringToBytes32(*sharedKey)

	decryptedBytes, err := manager.DecryptBytesWithSharedKey(encryptedMessageBytes, &sharedKeyBytes)
	if err != nil {
		return "", err
	}
	return BytesToStringUTF8(decryptedBytes), nil
}

func (manager *CryptoManager) DecryptBytesWithSharedKey(messageBytes []byte, sharedKeyBytes *[32]byte) (decryptedMessage []byte, err error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], messageBytes[:24])

	decryptedBytes, ok := box.OpenAfterPrecomputation(nil, messageBytes[24:], &decryptNonce, sharedKeyBytes)
	if !ok {
		return nil, errors.New("error decrypting")
	}
	return decryptedBytes, nil
}

func (manager *CryptoManager) DecryptStringUTF8(senderPublicKey, recipientPrivateKey, encryptedMessage string) (decryptedMessage string, err error) {
	sharedKeyBytes, _ := manager.GetSharedKeyInBytesByBase64Keys(&senderPublicKey, &recipientPrivateKey)
	encryptedMessageBytes := []byte(encryptedMessage)
	decryptedBytes, err := manager.DecryptBytesWithSharedKey(encryptedMessageBytes, &sharedKeyBytes)
	return BytesToStringUTF8(decryptedBytes), err
}