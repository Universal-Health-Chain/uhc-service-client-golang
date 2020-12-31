package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type ConnectionsService struct {
	ConnectionUhcController ConnectionUhcController
	MessageUhcController MessageUhcController
}

func (connectionsService *ConnectionsService) Initialize(backendUrl string) {
	connectionsService.ConnectionUhcController = ConnectionUhcController{models.Service{BackendUrl: backendUrl}}
	connectionsService.MessageUhcController = MessageUhcController{models.Service{BackendUrl: backendUrl}}
}

func (connectionsService *ConnectionsService) SetToken(token string) {
	connectionsService.ConnectionUhcController.Token = token
	connectionsService.MessageUhcController.Token = token
}

func (connectionsService *ConnectionsService) SetServiceToken(token string) {
	connectionsService.ConnectionUhcController.ServiceToken = token
	connectionsService.MessageUhcController.ServiceToken = token
}