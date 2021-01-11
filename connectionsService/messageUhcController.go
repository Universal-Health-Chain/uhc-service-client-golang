/* Copyright 2021 Fundación UNID */
package connectionsService

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
	_ "os"
)

type MessageUhcController struct {
	models.Service
}

func (connectionUhcController *MessageUhcController) SendMessageUhc(message models.MessageUHC) (*models.MessageUHCResponse, error) {
	messageUhcResponse := models.MessageUHCResponse{}

	jsonValue, _ := json.Marshal(message)

	url := connectionUhcController.BackendUrl + connectionsRoute + SendMessageUhc

	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+connectionUhcController.Token)
	request.Header.Set("x-serviceClient-uhc", "pushTokenController")

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

	_ = json.Unmarshal(body, &messageUhcResponse)

	return &messageUhcResponse, nil
}