package authService

import (
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

	resp, errata := externalTokenUserActionsController.CreateNewUserAndKeyIfNotExists(externalUserCreationRequest, organizationTokenForTesting)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	assert.Equal(t, email, resp.Data[0].Email )
}

func TestExternalTokenUserActionsController_CreateNewUserAndKeyIfNotExistsExistingUser(t *testing.T) {
	email := "inventedemail@email.com"
	_, _ = authController.RegisterDeletingForTesting(usernameTesting, email, userPwTesting)


	externalUserCreationRequest := models.UserExternalCreationRequest{Email: email}

	resp, errata := externalTokenUserActionsController.CreateNewUserAndKeyIfNotExists(externalUserCreationRequest, organizationTokenForTesting)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	//assert.Equal(t, email, resp.Data[0].Email )
	assert.Equal(t, resp.Code, 204 )
}