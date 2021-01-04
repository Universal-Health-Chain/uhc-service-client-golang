package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

var messageUhcController MessageUhcController
var encryptionKey authService.EncryptionKeyUserController

func init() {
	messageUhcController = MessageUhcController{models.Service{BackendUrl: backendUrl}}
	encryptionKey = authService.EncryptionKeyUserController{models.Service{BackendUrl: backendUrl}}

}

func TestConnectionUhcController_SendMessageUhc(t *testing.T) {
	user1, _ := authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	user2, _ := authController.RegisterDeletingForTesting(usernameTesting+"2test", emailTesting+"2test", userPwTesting+"2test")

	encryptionKeyRequest := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user1.Token
	encryptionKey.CreateUserEncryptionKey(encryptionKeyRequest)

	encryptionKeyRequest2 := models.KeyCreationRequest{AccessPassword: "sharedTest", Tag: "tag test"}
	encryptionKey.Token = user2.Token
	encryptionKey.CreateUserEncryptionKey(encryptionKeyRequest2)

	implicitConnectionRequest := models.ConnectionCreationImplicitRequest{}
	implicitConnectionRequest.ImplicitInvitationTokenInitiator = *user2.ImplicitInvitationToken
	implicitConnectionRequest.ImplicitInitiatorUserId = user2.ID

	connectionUhcController.Token = user1.Token
	connResp, _ := connectionUhcController.CreateConnectionUHCImplicitInvitation(implicitConnectionRequest)

	connection := connResp.Data[0]

	message := models.MessageUHC{}
	message.ID = "test"
	payload := models.UHCPayload{PayloadBase64: "test"}
	message.UHCPayload = &payload
	message.ConnectionUhcId = connection.ID
	message.FromUserId = user1.ID
	message.ToUserId = user2.ID

	messageUhcController.Token = user1.Token
	messResp, err := messageUhcController.SendMessageUhc(message)
	assert.Nil(t, err)
	assert.NotNil(t, messResp.Data[0])


}
