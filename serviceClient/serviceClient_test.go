package serviceClient

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestServiceClient_Initialize(t *testing.T) {
	serviceClient := ServiceClient{}
	backendUrl := os.Getenv("BACKENDURL")

	serviceClient.Initialize(backendUrl)

	assert.Equal(t, serviceClient.UsersService.PushTokenUHCController.BackendUrl, backendUrl)
	assert.Equal(t, serviceClient.ConnectionsService.ConnectionUhcController.BackendUrl, backendUrl)
}