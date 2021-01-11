/* Copyright 2021 Fundación UNID */
package serviceClient

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

func (serviceClient *ServiceClient) SetToken(token string) {
	serviceClient.AuthService.SetToken(token)
	serviceClient.ConnectionsService.SetToken(token)
	serviceClient.UsersService.SetToken(token)
}

func (serviceClient *ServiceClient) SetServiceToken(token string) {
	serviceClient.AuthService.SetServiceToken(token)
	serviceClient.ConnectionsService.SetServiceToken(token)
	serviceClient.UsersService.SetServiceToken(token)
}