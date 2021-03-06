/* Copyright 2021 Fundación UNID */
package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)


var cryptoController CryptoController


func init(){
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	cryptoController = CryptoController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

func Test_GetSharedEncryptionKeyRequest(t *testing.T) {

	//hacer login
	userResp, err := authController.Login(usernameTesting, userPwTesting)
	// con su token crear encryptiion key
	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	encryptionKeyUserController.Token = userResp.Data[0].Token

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest",Tag: "tag test"}
	encryptedKey, errata := encryptionKeyUserController.CreateUserEncryptionKey(encryptionKeyRequest)
	assert.Nil(t, errata, "errata should be nil")

	cryptoController.Token = userResp.Data[0].Token

	sharedKeyRequest := models.SharedKeyCreationRequest{AccessPassword: encryptionKeyRequest.AccessPassword,OtherPartPublicKey: encryptedKey.Data[0].PublicKeyBase64}
	sharedKeyResponse, error := cryptoController.GetSharedEncryptionKeyRequest(sharedKeyRequest)
	assert.Nil(t, error, "error should be nil")
	assert.Equal(t, sharedKeyResponse.Data[0].OtherPartPublicKey, encryptedKey.Data[0].PublicKeyBase64)
	assert.NotEqual(t,  sharedKeyResponse.Data[0].SharedKey, "" )


}


func TestCryptoController_EncryptPayloadUsingEncryptionRequest(t *testing.T) {
	userResp, err := authController.Login(usernameTesting, userPwTesting)

	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	encryptionKeyUserController.Token = userResp.Data[0].Token

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest",Tag: "tag test"}
	encryptedKey, errata := encryptionKeyUserController.CreateUserEncryptionKey(encryptionKeyRequest)
	assert.Nil(t, errata, "errata should be nil")

	cryptoController.Token = userResp.Data[0].Token
	payload := "1234"
	encryptionRequest := models.EncryptionRequest{EncryptionKeyId:encryptedKey.Data[0].ID, AccessPassword: encryptionKeyRequest.AccessPassword, Payload: payload, OtherPartPublicKeyBase64: encryptedKey.Data[0].PublicKeyBase64}
	encryptedResp, error := cryptoController.EncryptPayloadUsingEncryptionRequest(encryptionRequest)

	assert.Nil(t, error, "error should be nil")
	assert.NotNil(t,  encryptedResp.Data)
	assert.NotNil(t,  encryptedResp.Data[0])
	assert.NotEqual(t, encryptedResp.Data[0].EncryptedMessageBase64, "")
}