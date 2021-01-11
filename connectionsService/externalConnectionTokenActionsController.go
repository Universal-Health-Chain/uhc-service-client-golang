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

type ExternalConectionTokenActionsController struct {
	models.Service
}


func (controller *ExternalConectionTokenActionsController) CreateConnectionUHCExternally(creationRequest models.ConnectionExternalCreationRequest) (*models.ConnectionUHCResponse, error) {
	connectionUhcResponse := models.ConnectionUHCResponse{}
	url := controller.BackendUrl + connectionsRoute + CreateConnectionUHCExternally
	jsonValue, _ := json.Marshal(creationRequest)

	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+controller.Token)
	request.Header.Set("x-service-token", controller.ServiceToken)

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

	_ = json.Unmarshal(body, &connectionUhcResponse)

	return &connectionUhcResponse, nil
}


func (controller *ExternalConectionTokenActionsController) SendMessageUhcExternally(message models.MessageUHC) (*models.MessageUHCResponse, error) {
	messageUHCResponse := models.MessageUHCResponse{}
	url := controller.BackendUrl + connectionsRoute + SendMessageUhcExternally
	jsonValue, _ := json.Marshal(message)

	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+controller.Token)
	request.Header.Set("x-service-token", controller.ServiceToken)

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

	_ = json.Unmarshal(body, &messageUHCResponse)

	return &messageUHCResponse, nil
}
