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
	"strings"
)

type ConnectionUhcController struct {
	models.Service
}

const connectionsRoute = "/connections"

func (connectionUhcController *ConnectionUhcController) GetConnectionUHCById(connectionId string) (*models.ConnectionUHCResponse, error) {
	connectionUhcResponse := models.ConnectionUHCResponse{}
	url := strings.ReplaceAll(connectionUhcController.BackendUrl + connectionsRoute + GetConnectionUHCById, "{connectionId}", connectionId)

	request, _ := http.NewRequest("GET", url, nil)
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

	_ = json.Unmarshal(body, &connectionUhcResponse)

	return &connectionUhcResponse, nil
}

func (connectionUhcController *ConnectionUhcController) CreateConnectionUHCImplicitInvitation(connectionCreationRequest models.ConnectionCreationImplicitRequest) (*models.ConnectionUHCResponse, error) {

	var connectionUhcResponse *models.ConnectionUHCResponse
	jsonValue, _ := json.Marshal(connectionCreationRequest)

	//url := "http://localhost:8000"+ CreateConnectionUHCImplicitInvitation
	url := connectionUhcController.BackendUrl + connectionsRoute + CreateConnectionUHCImplicitInvitation
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + connectionUhcController.Token)

	request.Header.Set("x-serviceClient-uhc", "connectionsService")

	client := &http.Client{}
	response, err := client.Do(request)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
		return nil, err
	}

	_ = json.Unmarshal(body, &connectionUhcResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return connectionUhcResponse, errors.New(message)
	}

	return connectionUhcResponse, nil

}

