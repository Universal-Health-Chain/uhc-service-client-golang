package connectionsService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type ConnectionsService struct {
	ConnectionUhcController ConnectionUhcController
}

func (connectionsService *ConnectionsService) Initialize(backendUrl string) {
	connectionsService.ConnectionUhcController = ConnectionUhcController{models.Service{BackendUrl: backendUrl}}
}

func (connectionsService *ConnectionsService) SetToken(token string) {
	connectionsService.ConnectionUhcController.Token = token
}