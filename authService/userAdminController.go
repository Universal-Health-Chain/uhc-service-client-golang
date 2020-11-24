package authService

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Universal-Health-Chain/uhc-service-client-golang/models"
	"io/ioutil"
	"net/http"
)

type UserAdminController struct {
	models.Service
}

const authRoute = "/auth"

func (userAdminController *UserAdminController) FindUserById(id string) (*models.UserResponse, error) {
	var userResponse *models.UserResponse

	retrievalToken := "test"
	url := userAdminController.BackendUrl + authRoute + FindUser + "?id=" + id + "&retrievalToken=" +retrievalToken
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userAdminController.Token)

	request.Header.Set("x-serviceClient-uhc", "userAdminController")

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

	_ = json.Unmarshal(body, &userResponse)

	if response.StatusCode != 200 {
		message := fmt.Sprintf("the transaction failed with code %v", response.StatusCode)
		return userResponse, errors.New(message)
	}

	return userResponse, nil
}