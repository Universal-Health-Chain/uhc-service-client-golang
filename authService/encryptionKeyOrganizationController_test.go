/* Copyright 2021 Fundación UNID */
package authService

import (
	fhir4 "github.com/Universal-Health-Chain/golang-fhir-models-uhc/fhir-models/fhir"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var encryptionKeyOrganization EncryptionKeyOrganizationController

func init() {
	godotenv.Load("../.env")
	backendUrl = os.Getenv("BACKENDURL")
	encryptionKeyOrganization = EncryptionKeyOrganizationController{models.Service{BackendUrl: backendUrl}}
	usernameTesting = os.Getenv("USERNAMETEST")
	userPwTesting = os.Getenv("PASSWORDTEST")
}

func Test_EncryptionKeyOrganizationCreationController(t *testing.T) {
	organization:= fhir4.Organization{}
	name := "test name " + StringWithCharset(10, "abcdefghijklmnopqrstuvwxyz123456789")
	organization.Name = &name

	user, err := authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	token := user.Token
	assert.NotEqual(t, token, "")

	organizationUHCController.Token = user.Token

	responseVc, err := organizationUHCController.CreateOrganizationUHCFromFhir(organization)
	assert.Nil(t, err, "errata should be nil")
	assert.NotNil(t, responseVc.Data[0].Subject)

	orgId := responseVc.Data[0].Subject.UhcPublicExtensions.OrganizationId

	assert.Nil(t, err, "err should be nil")
	assert.NotEqual(t, token, "")

	encryptionKeyOrganization.Token = user.Token

	encryptionKeyRequest := models.KeyCreationOrganizationRequest{Tag: "tag test", OrganizationId: orgId}
	keyResp, errata := encryptionKeyOrganization.CreateOrganizationEncryptionKey(encryptionKeyRequest)
	assert.Nil(t, errata, "errata should be nil")

	resp, errata := encryptionKeyOrganization.GetOrganizationPublicInfoOfActiveKey(orgId)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	assert.Equal(t, keyResp.Data[0].ID, resp.Data[0].ID)
	assert.Equal(t, resp.Data[0].Tag, encryptionKeyRequest.Tag)
//bc141d5f-fb10-4ab8-a8b4-74e01c59a66c
}



func Test_PublicInfo(t *testing.T) {
	//t.Skip()
	user, _ := authController.RegisterDeletingForTesting(usernameTesting, emailTesting, userPwTesting)
	token := user.Token

	orgId := "bc141d5f-fb10-4ab8-a8b4-74e01c59a66c"
	encryptionKeyOrganization.Token = token

	resp, errata := encryptionKeyOrganization.GetOrganizationPublicInfoOfActiveKey(orgId)
	assert.Nil(t, errata, "errata should be nil")
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Data[0].Tag)
	//bc141d5f-fb10-4ab8-a8b4-74e01c59a66c
}
