/* Copyright 2021 Fundación UNID */
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

func (connectionsService *UsersService) SetToken(token string) {
	connectionsService.PushTokenUHCController.Token = token
}

func (connectionsService *UsersService) SetServiceToken(token string) {
	connectionsService.PushTokenUHCController.ServiceToken = token
}