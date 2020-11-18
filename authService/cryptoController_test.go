package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/service"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)


var cryptoController CryptoController


func init(){
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	cryptoController = CryptoController{service.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

////////////
func Test_GetSharedEncryptionKeyRequest(t *testing.T) {

	//hacer login
	userResp, err := userAdminCon.Login(usernameTesting, userPwTesting)
	// con su token crear encryptiion key
	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	cryptoController.Token = userResp.Data[0].Token

	encryptionKeyRequest := models.EncryptionKeyCreationRequest{AccessPassword: "sharedTest",Tag: "tag test"}
	encryptedKey, errata := cryptoController.EncryptionKeyCreationController(encryptionKeyRequest)
	assert.Nil(t, errata, "errata should be nil")

	//haga shared key con la pública del 1 y el access passwd del 2
	sharedKeyRequest := models.SharedKeyCreationRequest{AccessPassword: encryptionKeyRequest.AccessPassword,OtherPartPublicKey: encryptedKey.Data[0].PublicKeyBase64}

	//probar la función
	sharedKeyResponse, error := cryptoController.GetSharedEncryptionKeyRequest(sharedKeyRequest)
	assert.Nil(t, error, "error should be nil")
	assert.Equal(t, sharedKeyResponse.Data[0].OtherPartPublicKey, encryptedKey.Data[0].PublicKeyBase64)
	assert.NotEqual(t,  sharedKeyResponse.Data[0].SharedKey, "" )


}
