package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var organizationTokenUHCController OrganizationTokenUHCController
var organizationTokenForTesting string
var emailTesting string
func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	emailTesting = usernameTesting + "@email.com"

	organizationTokenUHCController = OrganizationTokenUHCController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
	organizationTokenForTesting = os.Getenv("ORGANIZATIONTOKENTESTING")
}


func TestOrganizationTokenUHCController_GetOrganizationUHCTokenByToken(t *testing.T) {
	_, _ = authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)

	//encryptionKey.Token = userResp.Data[0].Token

	resp, errata := organizationTokenUHCController.GetOrganizationUHCTokenByToken(organizationTokenForTesting)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	assert.Equal(t, organizationTokenForTesting, resp.Data[0].Token )
}


func TestOrganizationTokenUHCController_GetOrganizationUHCTokenById(t *testing.T) {
	_, _ = authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)


	//encryptionKey.Token = userResp.Data[0].Token

	resp, _ := organizationTokenUHCController.GetOrganizationUHCTokenByToken(organizationTokenForTesting)
	tokenId := resp.Data[0].ID

	resp, _ = organizationTokenUHCController.GetOrganizationUHCTokenById(tokenId)

	assert.Equal(t, organizationTokenForTesting, resp.Data[0].Token )
	assert.Equal(t, tokenId, resp.Data[0].ID )
}