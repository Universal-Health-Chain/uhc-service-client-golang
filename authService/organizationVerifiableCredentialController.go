/* Copyright 2021 Fundación UNID */
package authService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
)

type OrganizationVerifiableCredentialController struct {
	models.Service
}

func (orgaizationVerifiableCredentialController *OrganizationVerifiableCredentialController) CreateOrganizationCredential(organizationCredential models.OrganizationVC) (*models.OrganizationVCResponse, error) {

	jsonValue, _ := json.Marshal(organizationCredential)
	organizationVCResponse := models.OrganizationVCResponse{}
	url := orgaizationVerifiableCredentialController.BackendUrl + authRoute + CreateOrganizationCredential
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+orgaizationVerifiableCredentialController.Token)
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


func (orgaizationVerifiableCredentialController *OrganizationVerifiableCredentialController) GetOrganizationVCByCredentialId(organizationCredentialId string) (*models.OrganizationVCResponse, error) {

	organizationVCResponse := models.OrganizationVCResponse{}
	url := orgaizationVerifiableCredentialController.BackendUrl + authRoute + GetOrganizationVCByCredentialId + "?id=" + organizationCredentialId

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+orgaizationVerifiableCredentialController.Token)
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