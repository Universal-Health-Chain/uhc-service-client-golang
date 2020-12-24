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

type ExternalTokenUserActionsController struct {
	models.Service
}

func (externalTokenUserActionsController *ExternalTokenUserActionsController) CreateNewUserAndKeyIfNotExists(userExternalCreationRequest models.UserExternalCreationRequest, serviceToken string) (*models.UserResponse, error) {

	jsonValue, _ := json.Marshal(userExternalCreationRequest)
	userResponse := models.UserResponse{}
	url := externalTokenUserActionsController.BackendUrl + authRoute + CreateNewUserAndKeyIfNotExists
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	request.Header.Set("Content-Type", "application/json")
	//request.Header.Set("Authorization", "Bearer "+externalTokenUserActionsController.Token)
	request.Header.Set("x-serviceClient-uhc", "ExternalTokenUserActionsController")
	request.Header.Set("x-service-token", serviceToken)

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

	if err != nil && response.StatusCode != 204 {
		userResponse = models.UserResponse{Message: "user exists", Code: 204, Data: nil}
		return &userResponse, nil
	}

	return &userResponse, nil
}