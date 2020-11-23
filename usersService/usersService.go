package usersService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type UsersService  struct {
	PushTokenUHCController PushTokenUHCController
}

func (connectionsService *UsersService) Initialize(backendUrl string) {
	connectionsService.PushTokenUHCController = PushTokenUHCController{models.Service{BackendUrl: backendUrl}}
}
