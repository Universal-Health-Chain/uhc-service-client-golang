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

type ExternalTokenUserActionsController struct {
	models.Service
}

func (externalTokenUserActionsController *ExternalTokenUserActionsController) CreateNewUserAndKeyIfNotExists(userExternalCreationRequest models.UserExternalCreationRequest) (*models.UserResponse, error) {

	jsonValue, _ := json.Marshal(userExternalCreationRequest)
	userResponse := models.UserResponse{}
	url := externalTokenUserActionsController.BackendUrl + authRoute + CreateNewUserAndKeyIfNotExists
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+externalTokenUserActionsController.Token)
	request.Header.Set("x-serviceClient-uhc", "ExternalTokenUserActionsController")
	request.Header.Set("x-service-token", externalTokenUserActionsController.ServiceToken)

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

	err = json.Unmarshal(body, &userResponse)


	if response.StatusCode != 200 && response.StatusCode != 204 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return &userResponse, errors.New(message)
	}

	if err != nil && response.StatusCode == 204 {
		userResponse = models.UserResponse{Message: "user exists", Code: 204, Data: nil}
		return &userResponse, nil
	}

	return &userResponse, nil
}




func (externalTokenUserActionsController *ExternalTokenUserActionsController) GetOrganizationPublicInfoOfActiveKeyExternally(organizationId string) (*models.PublicInfoFromKeyResponse, error) {

	publicInfoResponse := models.PublicInfoFromKeyResponse{}
	url := strings.ReplaceAll(externalTokenUserActionsController.BackendUrl + authRoute + GetOrganizationPublicInfoOfActiveKeyExternally, "{organizationId}", organizationId)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+externalTokenUserActionsController.Token)
	request.Header.Set("x-serviceClient-uhc", "ExternalTokenUserActionsController")
	request.Header.Set("x-service-token",externalTokenUserActionsController.ServiceToken )

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

	if err != nil && response.StatusCode == 204 {
		publicInfoResponse = models.PublicInfoFromKeyResponse{Message: "user exists", Code: 204, Data: nil}
		return &publicInfoResponse, nil
	}

	return &publicInfoResponse, nil
}



func (externalTokenUserActionsController *ExternalTokenUserActionsController) GetUserPublicInfoOfActiveKeyExternally(email string) (*models.PublicInfoFromKeyResponse, error) {

	publicInfoResponse := models.PublicInfoFromKeyResponse{}
	url := externalTokenUserActionsController.BackendUrl +authRoute + GetUserPublicInfoOfActiveKeyExternally + "?email=" + email
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+externalTokenUserActionsController.Token)
	request.Header.Set("x-serviceClient-uhc", "ExternalTokenUserActionsController")
	request.Header.Set("x-service-token",externalTokenUserActionsController.ServiceToken )

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

	if err != nil && response.StatusCode == 204 {
		publicInfoResponse = models.PublicInfoFromKeyResponse{Message: "user exists", Code: 204, Data: nil}
		return &publicInfoResponse, nil
	}

	return &publicInfoResponse, nil
}

func (externalTokenUserActionsController *ExternalTokenUserActionsController) EncryptPayloadUsingEncryptionRequestExternally(encryptionRequest models.EncryptionRequest) (*models.EncryptedResultResponse, error) {

	var encryptedResultResponse *models.EncryptedResultResponse
	jsonValue, _ := json.Marshal(encryptionRequest)

	url := externalTokenUserActionsController.BackendUrl + authRoute + EncryptPayloadUsingEncryptionRequestExternally
	request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer " + externalTokenUserActionsController.Token)
	request.Header.Set("x-service-token",externalTokenUserActionsController.ServiceToken )

	request.Header.Set("x-serviceClient-uhc", "connectionsService")

	client := &http.Client{}
	response, err := client.Do(request)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &encryptedResultResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return encryptedResultResponse, errors.New(message)
	}

	return encryptedResultResponse, nil

}