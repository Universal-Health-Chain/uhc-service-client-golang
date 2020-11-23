package usersService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/service"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var backendUrl string
var usernameTesting string
var userPwTesting string
var pushTokenController PushTokenUHCController
var authController authService.AuthController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	pushTokenController = PushTokenUHCController{service.Service{BackendUrl: backendUrl}}
	authController = authService.AuthController{service.Service{BackendUrl: backendUrl}}

}

func TestPushTokenUHCController_GetPushTokensByUHCId(t *testing.T) {
	loginResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, loginResp.Data[0].Username, usernameTesting)

	pushTokenController.Token = loginResp.Data[0].Token
	id := loginResp.Data[0].ID

	pushTokenResponse, err := pushTokenController.GetPushTokensByUHCId(id)
	assert.NotNil(t, pushTokenResponse.DataResponse[0])

}
