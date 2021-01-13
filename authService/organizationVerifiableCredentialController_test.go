/* Copyright 2021 Fundación UNID */
package authService

import (
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"os"
	"testing"
)

var organizationVcController OrganizationVerifiableCredentialController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	organizationVcController = OrganizationVerifiableCredentialController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

func TestOrgaizationVerifiableCredentialController_CreateOrganizationCredential(t *testing.T) {
}
