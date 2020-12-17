package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var backendUrl string
var usernameTesting string
var userPwTesting string
var emailTesting string
var connectionUhcController ConnectionUhcController
var userAdminCon authService.UserAdminController
var authController authService.AuthController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	emailTesting = usernameTesting + "@email.com"
	connectionUhcController = ConnectionUhcController{models.Service{BackendUrl: backendUrl}}
	userAdminCon = authService.UserAdminController{models.Service{BackendUrl: backendUrl}}
	authController = authService.AuthController{models.Service{BackendUrl: backendUrl}}

}

func TestPushTokenUHCController_GetPushTokensByUHCId(t *testing.T) {
	user1, _ := authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	user2, _ := authController.RegisterDeletingForTesting(usernameTesting+"2test", emailTesting+"2test", userPwTesting+"2test")

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user1.Token
	encryptionKey.CreateEncryptionKey(encryptionKeyRequest)

	encryptionKeyRequest2 := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user2.Token
	encryptionKey.CreateEncryptionKey(encryptionKeyRequest2)

	implicitConnectionRequest := models.ConnectionCreationImplicitRequest{}
	implicitConnectionRequest.ImplicitInvitationTokenInitiator = *user2.ImplicitInvitationToken
	implicitConnectionRequest.ImplicitInitiatorUserId = user2.ID

	connectionUhcController.Token = user1.Token
	connResp, err := connectionUhcController.CreateConnectionUHCImplicitInvitation(implicitConnectionRequest)
	assert.Nil(t, err)
	assert.NotNil(t, connResp.Data[0])
}
