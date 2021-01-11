/* Copyright 2021 Fundación UNID */
package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var encryptionKeyUserController EncryptionKeyUserController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	encryptionKeyUserController = EncryptionKeyUserController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

func Test_EncryptionKeyCreationController(t *testing.T) {
	userResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	encryptionKeyUserController.Token = userResp.Data[0].Token

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	_, errata := encryptionKeyUserController.CreateUserEncryptionKey(encryptionKeyRequest)
	assert.Nil(t, errata, "errata should be nil")
}

func TestEncryptionKeyController_GetUserPublicInfoOfActiveKeyController(t *testing.T) {
	userResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	encryptionKeyUserController.Token = userResp.Data[0].Token

	resp, errata := encryptionKeyUserController.GetUserPublicInfoOfActiveKey(userResp.Data[0].ID)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
}
