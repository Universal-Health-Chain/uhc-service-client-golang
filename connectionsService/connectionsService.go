package connectionsService

import "github.com/Universal-Health-Chain/uhc-service-client-golang/service"

type ConnectionsService struct {
	ConnectionUhcController ConnectionUhcController
}

func (connectionsService *ConnectionsService) Initialize(backendUrl string) {
	connectionsService.ConnectionUhcController = ConnectionUhcController{service.Service{BackendUrl: backendUrl}}
}