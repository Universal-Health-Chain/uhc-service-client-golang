package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type AuthService  struct {
	AuthController                             AuthController
	CryptoController                           CryptoController
	EncryptionKeyController                    EncryptionKeyController
	UserAdminController                        UserAdminController
	OrganizationVerifiableCredentialController OrganizationVerifiableCredentialController
	OrganizationUHCController OrganizationUHCController
	OrganizationTokenUHCController OrganizationTokenUHCController
}

func (authService *AuthService) Initialize(backendUrl string) {
	authService.AuthController = AuthController{models.Service{BackendUrl: backendUrl}}
	authService.CryptoController = CryptoController{models.Service{BackendUrl: backendUrl}}
	authService.EncryptionKeyController = EncryptionKeyController{models.Service{BackendUrl: backendUrl}}
	authService.UserAdminController = UserAdminController{models.Service{BackendUrl: backendUrl}}
	authService.OrganizationVerifiableCredentialController = OrganizationVerifiableCredentialController{models.Service{BackendUrl: backendUrl}}
	authService.OrganizationUHCController = OrganizationUHCController{models.Service{BackendUrl: backendUrl}}
	authService.OrganizationTokenUHCController = OrganizationTokenUHCController{models.Service{BackendUrl: backendUrl}}
}

func (authService *AuthService) SetToken(token string) {
	authService.AuthController.Token = token
	authService.CryptoController.Token = token
	authService.EncryptionKeyController.Token = token
	authService.UserAdminController.Token = token
	authService.OrganizationVerifiableCredentialController.Token = token
	authService.OrganizationUHCController.Token = token
	authService.OrganizationTokenUHCController.Token = token
}
