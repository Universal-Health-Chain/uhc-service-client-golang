package authService

import "github.com/Universal-Health-Chain/uhc-service-client-golang/service"

type AuthService  struct {
	AuthController AuthController
	CryptoController CryptoController
	EncryptionKeyController EncryptionKeyController
	UserAdminController UserAdminController
}

func (authService *AuthService) Initialize(backendUrl string) {
	authService.AuthController = AuthController{service.Service{BackendUrl: backendUrl}}
	authService.CryptoController = CryptoController{service.Service{BackendUrl: backendUrl}}
	authService.EncryptionKeyController = EncryptionKeyController{service.Service{BackendUrl: backendUrl}}
	authService.UserAdminController = UserAdminController{service.Service{BackendUrl: backendUrl}}
}
