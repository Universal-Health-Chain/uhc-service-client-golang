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
	user,_ := authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	token := user.Token

	//encryptionKey.Token = userResp.Data[0].Token

	respToken, _ := organizationTokenUHCController.GetOrganizationUHCTokenByToken(organizationTokenForTesting)
	tokenId := respToken.Data[0].ID

	respId, _ := organizationTokenUHCController.GetOrganizationUHCTokenById(tokenId)

	assert.Equal(t, organizationTokenForTesting, respId.Data[0].Token )
	assert.Equal(t, tokenId, respId.Data[0].ID )

	user, _ = authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	token = user.Token
	encryptionKeyOrganization.Token = token
	orgId := respToken.Data[0].OrganizationOwnerId

	resp, errata := encryptionKeyOrganization.GetOrganizationPublicInfoOfActiveKey(orgId)
	assert.NotNil(t, resp)
	assert.Nil(t, errata)
	assert.NotNil(t, resp.Data[0].ID)
	assert.NotNil(t, resp.Data[0].Tag)
}