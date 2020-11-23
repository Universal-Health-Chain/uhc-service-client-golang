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

type EncryptionKeyController struct {
	models.Service
}


func (encryptionKeyController *EncryptionKeyController) CreateEncryptionKey(encryptionKeyRequest models.EncryptionKeyCreationRequest) (*models.EncryptionKeyResponse, error) {

	var encryptionKeyResponse *models.EncryptionKeyResponse
	jsonValue, _ := json.Marshal(encryptionKeyRequest)

	url := encryptionKeyController.BackendUrl + authRoute + CreateEncryptionKey
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + encryptionKeyController.Token)

	request.Header.Set("x-serviceClient-uhc", "connectionsService")

	client := &http.Client{}
	response, err := client.Do(request)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return nil, errors.New(message)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &encryptionKeyResponse)
	return encryptionKeyResponse, nil

}


func (encryptionKeyController *EncryptionKeyController) GetUserPublicInfoOfActiveKey(uhcId string) (*models.PublicInfoFromKeyResponse, error) {
	publicInfoResponse := models.PublicInfoFromKeyResponse{}
	url := strings.ReplaceAll(encryptionKeyController.BackendUrl + authRoute + GetUserPublicInfoOfActiveKey, "{userId}", uhcId)

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

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return nil, errors.New(message)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &publicInfoResponse)

	return &publicInfoResponse, nil

}
