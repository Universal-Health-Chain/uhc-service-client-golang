package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"os"
	"testing"
)

var organizationUHCController OrganizationUHCController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	organizationUHCController = OrganizationUHCController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

func TestOrganizationUHCController_CreateOrganizationCredential(t *testing.T) {
}
