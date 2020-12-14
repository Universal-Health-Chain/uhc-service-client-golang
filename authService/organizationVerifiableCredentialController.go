package authService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
	"strings"
)

type OrgaizationVerifiableCredentialController struct {
	models.Service
}

func (userAdminController *OrgaizationVerifiableCredentialController) CreateOrganizationCredential(organizationCredential models.OrganizationVC) (*models.OrganizationVCResponse, error) {

	jsonValue, _ := json.Marshal(organizationCredential)
	organizationVCResponse := models.OrganizationVCResponse{}
	url := userAdminController.BackendUrl + authRoute + CreateOrganizationCredential
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userAdminController.Token)
	request.Header.Set("x-serviceClient-uhc", "service-client")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &organizationVCResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &organizationVCResponse, errors.New(message)
	}

	return &organizationVCResponse, nil
}


func (userAdminController *OrgaizationVerifiableCredentialController) GetOrganizationVCByCredentialId(organizationCredentialId string) (*models.OrganizationVCResponse, error) {

	organizationVCResponse := models.OrganizationVCResponse{}
	url := strings.ReplaceAll(userAdminController.BackendUrl + authRoute + CreateOrganizationCredential, "{organizationId}", organizationCredentialId)

	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userAdminController.Token)
	request.Header.Set("x-serviceClient-uhc", "service-client")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &organizationVCResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &organizationVCResponse, errors.New(message)
	}

	return &organizationVCResponse, nil
}