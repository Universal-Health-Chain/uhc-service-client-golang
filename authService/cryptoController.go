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

type CryptoController struct {
	models.Service
}

func (cryptoController *CryptoController) DecryptPayloadUsingDecryptionRequest(decryptionRequest models.DecryptionRequest) (*models.EncryptedResultResponse, error) {

	var encryptedResultResponse *models.EncryptedResultResponse
	jsonValue, _ := json.Marshal(decryptionRequest)

	url := cryptoController.BackendUrl + authRoute + EncryptPayloadUsingEncryptionRequest
	request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + cryptoController.Token)

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


func (cryptoController *CryptoController) GetSharedEncryptionKeyRequest(sharedKeyRequest models.SharedKeyCreationRequest) (*models.SharedKeyResponse, error) {

	var sharedKeyResponse *models.SharedKeyResponse
	jsonValue, _ := json.Marshal(sharedKeyRequest)

	url := cryptoController.BackendUrl + authRoute + GetSharedEncryptionKey
	request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + cryptoController.Token)

	request.Header.Set("x-serviceClient-uhc", "connectionsService")

	client := &http.Client{}
	response, err := client.Do(request)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &sharedKeyResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return sharedKeyResponse, errors.New(message)
	}

	return sharedKeyResponse, nil

}