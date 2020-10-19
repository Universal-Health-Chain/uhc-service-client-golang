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
var configUHCController ConfigUHCController
var userAdminCon authService.UserAdminController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	configUHCController = ConfigUHCController{service.Service{BackendUrl: backendUrl}}
	userAdminCon = authService.UserAdminController{service.Service{BackendUrl: backendUrl}}
}

func TestConfigUHCController_GetUserConfigUHCByUhcId(t *testing.T) {
	loginResp, err := userAdminCon.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, loginResp.Data[0].Username, usernameTesting)

	configUHCController.Token = loginResp.Data[0].Token
	id := loginResp.Data[0].ID

	configResp, err := configUHCController.GetUserConfigUHCByUhcId(id)
	assert.NotNil(t, configResp.DataResponse[0])

}