package authService

import (
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
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
	organization:= fhir4.Organization{}
	name := "test name " + StringWithCharset(10, "abcdefghijklmnopqrstuvwxyz123456789")
	organization.Name = &name

	userResp, err := authController.Login(usernameTesting, userPwTesting)
	assert.Nil(t, err, "err should be nil")
	token := userResp.Data[0].Token
	assert.NotEqual(t, token, "")

	organizationUHCController.Token = userResp.Data[0].Token

	responseVc, err := organizationUHCController.CreateOrganizationUHCFromFhir(organization)
	assert.Nil(t, err, "errata should be nil")
	assert.NotNil(t, responseVc.Data[0].Subject)

	orgId := responseVc.Data[0].Subject.UhcPublicExtensions.OrganizationId
	response, err := organizationUHCController.GetOrganizationUHC(orgId)
	assert.Nil(t, err, "errata should be nil")
	assert.NotNil(t, response.Data[0].UhcPublicExtensions)

}
