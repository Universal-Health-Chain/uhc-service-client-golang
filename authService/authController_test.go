package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/service"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var authController AuthController
func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	authController = AuthController{service.Service{BackendUrl: backendUrl}}
}

func TestAuthController_Login(t *testing.T) {
	userResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "error should be nil")
	assert.Equal(t, userResp.Data[0].Username, usernameTesting)
}