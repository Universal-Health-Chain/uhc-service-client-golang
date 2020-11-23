package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"os"
	"testing"
)

var backendUrl string
var usernameTesting string
var userPwTesting string
var connectionUhcController ConnectionUhcController
var userAdminCon authService.UserAdminController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	connectionUhcController = ConnectionUhcController{models.Service{BackendUrl: backendUrl}}
	userAdminCon = authService.UserAdminController{models.Service{BackendUrl: backendUrl}}
}

func TestPushTokenUHCController_GetPushTokensByUHCId(t *testing.T) {

}
