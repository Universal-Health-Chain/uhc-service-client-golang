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
	"strings"
)

type EncryptionKeyOrganizationController struct {
	models.Service
}


func (encryptionKeyController *EncryptionKeyOrganizationController) CreateOrganizationEncryptionKey(encryptionKeyRequest models.KeyCreationOrganizationRequest) (*models.KeyResponse, error) {

	var encryptionKeyResponse *models.KeyResponse
	jsonValue, _ := json.Marshal(encryptionKeyRequest)

	url := encryptionKeyController.BackendUrl + authRoute + CreateOrganizationEncryptionKey
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + encryptionKeyController.Token)

	request.Header.Set("x-serviceClient-uhc", "connectionsService")

	client := &http.Client{}
	response, err := client.Do(request)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &encryptionKeyResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return encryptionKeyResponse, errors.New(message)
	}

	return encryptionKeyResponse, nil

}


func (encryptionKeyController *EncryptionKeyOrganizationController) GetOrganizationPublicInfoOfActiveKey(organizationId string) (*models.PublicInfoFromKeyResponse, error) {
	publicInfoResponse := models.PublicInfoFromKeyResponse{}
	url := strings.ReplaceAll(encryptionKeyController.BackendUrl + authRoute +GetOrganizationPublicInfoOfActiveKey, "{organizationId}", organizationId)

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+encryptionKeyController.Token)
	request.Header.Set("x-serviceClient-uhc", "encryptionKeyController")

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

	_ = json.Unmarshal(body, &publicInfoResponse)

	if response.StatusCode != 200 && response.StatusCode != 204 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &publicInfoResponse, errors.New(message)
	}
	return &publicInfoResponse, nil

}


func (encryptionKeyController *EncryptionKeyOrganizationController) GetPublicInfoOfEncryptionKey(encryptionKey string) (*models.PublicInfoFromKeyResponse, error) {
	publicInfoResponse := models.PublicInfoFromKeyResponse{}
	url := strings.ReplaceAll(encryptionKeyController.BackendUrl + authRoute + GetPublicInfoOfEncryptionKey, "{encryptionKeyUserController}", encryptionKey)

	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+encryptionKeyController.Token)
	request.Header.Set("x-serviceClient-uhc", "encryptionKeyController")

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

	err = json.Unmarshal(body, &publicInfoResponse)

	if response.StatusCode != 200 && response.StatusCode != 204 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &publicInfoResponse, errors.New(message)
	}

	return &publicInfoResponse, nil

}