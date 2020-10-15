package authService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
)

type CryptoController struct {
	Service
}

func (cryptoController *CryptoController) DecryptPayloadUsingDecryptionRequest(decryptionRequest models.DecryptionRequest) (*models.EncryptedResultResponse, error) {

	var encryptedResultResponse *models.EncryptedResultResponse
	jsonValue, _ := json.Marshal(decryptionRequest)

	url := cryptoController.BackendUrl + authRoute + EncryptPayloadUsingEncryptionRequest
	request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + cryptoController.Token)

	request.Header.Set("x-service-uhc", "connectionsService")

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

	_ = json.Unmarshal(body, &encryptedResultResponse)
	return encryptedResultResponse, nil

}
