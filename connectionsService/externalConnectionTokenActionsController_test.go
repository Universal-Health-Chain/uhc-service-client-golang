/* Copyright 2021 Fundación UNID */
package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"os"
	"testing"
	"time"
)

var externalConnectionTokenActions ExternalConectionTokenActionsController

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func LongRandomString() string {
	return StringWithCharset(8, "abcdefghijklmnopqrst1234567890")
}

var organizationTokenForTesting string
var organizationTokenUHCController authService.OrganizationTokenUHCController

func init() {
	godotenv.Load("../.env")
	organizationTokenUHCController = authService.OrganizationTokenUHCController{models.Service{BackendUrl: backendUrl}}
	externalConnectionTokenActions = ExternalConectionTokenActionsController{models.Service{BackendUrl: backendUrl}}
	organizationTokenForTesting = os.Getenv("ORGANIZATIONTOKENTESTING")
}

func TestExternalConectionTokenActionsController_CreateConnectionUHCExternally(t *testing.T) {
	user, _ := authController.RegisterDeletingForTesting(usernameTesting +LongRandomString(), emailTesting +LongRandomString(), userPwTesting)

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user.Token
	encryptionKey.CreateUserEncryptionKey(encryptionKeyRequest)


	organizationTokenUHCController.ServiceToken = organizationTokenForTesting
	respToken, errata := organizationTokenUHCController.GetOrganizationUHCTokenByToken(organizationTokenForTesting)
	assert.Nil(t, errata)
	assert.NotNil(t, respToken)

	creationRequest := models.ConnectionExternalCreationRequest{}
	creationRequest.OrganizationCreatorId = respToken.Data[0].OrganizationOwnerId
	creationRequest.InvitedUserEmail = user.Email

	externalConnectionTokenActions.ServiceToken = organizationTokenForTesting
	connResp, err := externalConnectionTokenActions.CreateConnectionUHCExternally(creationRequest)
	assert.Nil(t, err)
	assert.NotNil(t, connResp.Data[0])
}



func TestExternalConectionTokenActionsController_SendMessageUhcExternally(t *testing.T) {
	user, _ := authController.RegisterDeletingForTesting(usernameTesting +LongRandomString(), emailTesting +LongRandomString(), userPwTesting)

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user.Token
	encryptionKey.CreateUserEncryptionKey(encryptionKeyRequest)


	organizationTokenUHCController.ServiceToken = organizationTokenForTesting
	respToken, errata := organizationTokenUHCController.GetOrganizationUHCTokenByToken(organizationTokenForTesting)
	assert.Nil(t, errata)
	assert.NotNil(t, respToken)

	creationRequest := models.ConnectionExternalCreationRequest{}
	creationRequest.OrganizationCreatorId = respToken.Data[0].OrganizationOwnerId
	creationRequest.InvitedUserEmail = user.Email

	externalConnectionTokenActions.ServiceToken = organizationTokenForTesting
	connResp, err := externalConnectionTokenActions.CreateConnectionUHCExternally(creationRequest)
	assert.Nil(t, err)
	assert.NotNil(t, connResp.Data[0])

	connection := connResp.Data[0]

	message := models.MessageUHC{}
	message.ConnectionUhcId = connection.ID
	message.ToUserId = connection.InvitedUserId
	message.FromOrganizationId = connection.InitiatorOrganizationId
	message.Label = "test"

	messResp, err := externalConnectionTokenActions.SendMessageUhcExternally(message)
	assert.Nil(t, err)
	assert.NotNil(t, messResp.Data[0])
	assert.Equal(t, messResp.Data[0].FromOrganizationId, message.FromOrganizationId)
}
