package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type ConnectionsService struct {
	ConnectionUhcController ConnectionUhcController
	MessageUhcController MessageUhcController
	ExternalConectionTokenActionsController ExternalConectionTokenActionsController
}

func (connectionsService *ConnectionsService) Initialize(backendUrl string) {
	connectionsService.ConnectionUhcController = ConnectionUhcController{models.Service{BackendUrl: backendUrl}}
	connectionsService.MessageUhcController = MessageUhcController{models.Service{BackendUrl: backendUrl}}
	connectionsService.ExternalConectionTokenActionsController = ExternalConectionTokenActionsController{models.Service{BackendUrl: backendUrl}}
}

func (connectionsService *ConnectionsService) SetToken(token string) {
	connectionsService.ConnectionUhcController.Token = token
	connectionsService.MessageUhcController.Token = token
	connectionsService.ExternalConectionTokenActionsController.Token = token
}

func (connectionsService *ConnectionsService) SetServiceToken(token string) {
	connectionsService.ConnectionUhcController.ServiceToken = token
	connectionsService.MessageUhcController.ServiceToken = token
	connectionsService.ExternalConectionTokenActionsController.ServiceToken = token

}