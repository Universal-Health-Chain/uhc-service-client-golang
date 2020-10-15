package authService

import (
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var backendUrl string
var usernameTesting string
var userPwTesting string
var userAdminCon UserAdminController

func init() {
	godotenv.Load()
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	userAdminCon = UserAdminController{Service{BackendUrl: backendUrl}}
}

func TestAuthService_Login(t *testing.T) {
	userResp, err := userAdminCon.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)
}

func TestAuthService_FindUserById(t *testing.T) {
	loginResp, err := userAdminCon.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")

	id := loginResp.Data[0].ID
	token := loginResp.Data[0].Token

	userAdminCon.Token = token

	userResp, err := userAdminCon.FindUserById(id)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)
}
