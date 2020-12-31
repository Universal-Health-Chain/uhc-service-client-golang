package authService

import (
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var externalTokenUserActionsController ExternalTokenUserActionsController
func init() {
	externalTokenUserActionsController = ExternalTokenUserActionsController{models.Service{BackendUrl: backendUrl}}
}

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}


func TestExternalTokenUserActionsController_CreateNewUserAndKeyIfNotExists(t *testing.T) {
	email := "inventedemail@email.com" + StringWithCharset(5,"abcdefghijklmnopqrstuvwxyz123456789")

	externalUserCreationRequest := models.UserExternalCreationRequest{Email: email}
	externalTokenUserActionsController.ServiceToken = organizationTokenForTesting

	resp, errata := externalTokenUserActionsController.CreateNewUserAndKeyIfNotExists(externalUserCreationRequest)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	assert.Equal(t, email, resp.Data[0].Email )
}

func TestExternalTokenUserActionsController_CreateNewUserAndKeyIfNotExistsExistingUser(t *testing.T) {
	email := "inventedemail@email.com"
	_, _ = authController.RegisterDeletingForTesting(usernameTesting, email, userPwTesting)


	externalUserCreationRequest := models.UserExternalCreationRequest{Email: email}
	externalTokenUserActionsController.ServiceToken = organizationTokenForTesting

	resp, errata := externalTokenUserActionsController.CreateNewUserAndKeyIfNotExists(externalUserCreationRequest)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	//assert.Equal(t, email, resp.Data[0].Email )
	assert.Equal(t, resp.Code, 204 )
}

func TestExternalTokenUserActionsController_GetUserPublicInfoOfActiveKeyExternally(t *testing.T) {
	email := "inventedemailemail.com" + StringWithCharset(5,"abcdefghijklmnopqrstuvwxyz123456789")
	usernameTesting = StringWithCharset(5,"abcdefghijklmnopqrstuvwxyz123456789")

	user, _ := authController.RegisterDeletingForTesting(usernameTesting, email, userPwTesting)

	encryptionKey.Token = user.Token
	keyResp, err := encryptionKey.CreateUserEncryptionKey(models.KeyCreationRequest{Tag:"tag",AccessPassword: "1234"})
	assert.Nil(t, err, "errata should be nil")

	externalTokenUserActionsController.ServiceToken = organizationTokenForTesting
	resp, errata := externalTokenUserActionsController.GetUserPublicInfoOfActiveKeyExternally(email)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	//assert.Equal(t, email, resp.Data[0].Email )
	assert.Equal(t, resp.Data[0].PublicKeyBase64, keyResp.Data[0].PublicKeyBase64, 204 )
}

func TestExternalTokenUserActionsController_GetOrganizationPublicInfoOfActiveKeyExternally(t *testing.T) {
	email := "inventedemailemail.com" + StringWithCharset(5,"abcdefghijklmnopqrstuvwxyz123456789")
	usernameTesting = StringWithCharset(5,"abcdefghijklmnopqrstuvwxyz123456789")
	user, _ := authController.RegisterDeletingForTesting(usernameTesting, email, userPwTesting)
	token := user.Token

	organization:= fhir4.Organization{}
	name := "test name " + StringWithCharset(10, "abcdefghijklmnopqrstuvwxyz123456789")
	organization.Name = &name


	organizationUHCController.Token = token
	responseVc, err := organizationUHCController.CreateOrganizationUHCFromFhir(organization)

	assert.Nil(t, err, "errata should be nil")
	assert.NotNil(t, responseVc.Data[0].Subject)
	orgId :=responseVc.Data[0].Subject.UhcPublicExtensions.OrganizationId

	externalTokenUserActionsController.ServiceToken = organizationTokenForTesting
	resp, errata := externalTokenUserActionsController.GetOrganizationPublicInfoOfActiveKeyExternally(orgId)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)


}