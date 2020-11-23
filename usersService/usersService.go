package usersService

import "github.com/Universal-Health-Chain/uhc-service-client-golang/service"

type UsersService  struct {
	PushTokenUHCController PushTokenUHCController
}

func (connectionsService *UsersService) Initialize(backendUrl string) {
	connectionsService.PushTokenUHCController = PushTokenUHCController{service.Service{BackendUrl: backendUrl}}
}
