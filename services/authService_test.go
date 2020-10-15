package services

import (
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var backendUrl string
var usernameTesting string
var userPwTesting string
var authService AuthService

func init() {
	godotenv.Load()
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	authService = AuthService{Service{BackendUrl: backendUrl}}

}

func TestAuthService_Login(t *testing.T) {
	userResp, err := authService.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)

}

func TestAuthService_FindUserById(t *testing.T) {
	loginResp, err := authService.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")

	id := loginResp.Data[0].ID
	token := loginResp.Data[0].Token

	authService.Token = token


	userResp, err := authService.FindUserById(id)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)

}
