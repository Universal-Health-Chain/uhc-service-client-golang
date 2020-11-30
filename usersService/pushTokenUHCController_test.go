package usersService

import (
	"fmt"
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
var pushTokenController PushTokenUHCController
var authController authService.AuthController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	pushTokenController = PushTokenUHCController{models.Service{BackendUrl: backendUrl}}
	authController = authService.AuthController{models.Service{BackendUrl: backendUrl}}

}

func TestPushTokenUHCController_GetPushTokensByUHCId(t *testing.T) {
	t.Skip()
	loginResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, loginResp.Data[0].Username, usernameTesting)

	pushTokenController.Token = loginResp.Data[0].Token
	id := loginResp.Data[0].ID

	pushTokenResponse, err := pushTokenController.GetPushTokensByUHCId(id)
	fmt.Println(err)
	assert.NotNil(t, pushTokenResponse.DataResponse[0])

}
