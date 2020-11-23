package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type AuthService  struct {
	AuthController AuthController
	CryptoController CryptoController
	EncryptionKeyController EncryptionKeyController
	UserAdminController UserAdminController
}

func (authService *AuthService) Initialize(backendUrl string) {
	authService.AuthController = AuthController{models.Service{BackendUrl: backendUrl}}
	authService.CryptoController = CryptoController{models.Service{BackendUrl: backendUrl}}
	authService.EncryptionKeyController = EncryptionKeyController{models.Service{BackendUrl: backendUrl}}
	authService.UserAdminController = UserAdminController{models.Service{BackendUrl: backendUrl}}
}
