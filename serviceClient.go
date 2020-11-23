package main

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/authService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/connectionsService"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/usersService"
)

type ServiceClient  struct {
	AuthService authService.AuthService
	ConnectionsService connectionsService.ConnectionsService
	UsersService usersService.UsersService
}

func (serviceClient *ServiceClient) Initialize(backendUrl string) {
	serviceClient.AuthService.Initialize(backendUrl)
	serviceClient.ConnectionsService.Initialize(backendUrl)
	serviceClient.UsersService.Initialize(backendUrl)
}

